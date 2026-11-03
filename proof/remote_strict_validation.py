#!/usr/bin/env python3
"""Execute closed synthetic cases against the fixed strict controller."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from typing import Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import proof.remote_strict_controller as rsc
from proof.remote_strict_fixtures import FAKE_STAGE_EMITTER_SOURCE


def revision(path: str) -> str:
    return subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"], text=True).strip()


def canonical_drivers(w_path: str) -> list[str]:
    path = os.path.join(w_path, "proof", "proofkit.py")
    with open(path, encoding="utf-8") as f:
        module = ast.parse(f.read(), filename=path)
    for node in module.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == "DRIVERS_29" for t in targets):
                drivers = list(ast.literal_eval(node.value))
                if len(drivers) != 29 or len(set(drivers)) != 29 or not all(isinstance(d, str) for d in drivers):
                    raise ValueError("invalid W canonical driver inventory")
                return drivers
    raise ValueError("W canonical driver inventory missing")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remote strict synthetic validation")
    parser.add_argument("--mode", default="validation-only")
    parser.add_argument("--p", required=True)
    parser.add_argument("--w", required=True)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--artifacts-dir", default="strict-proof-artifacts")
    parser.add_argument("--case", choices=("success", "failed-plan", "failed-pin", "divergence", "cleanup-failure", "ownership-crash"), default="success")
    parser.add_argument("--case-data-dir", required=True)
    parser.add_argument("--job-start-time")
    parser.add_argument("--host-job-limit-sec", type=float, default=rsc.HOST_JOB_LIMIT_SEC)
    parser.add_argument("--payload-budget-sec", type=float, default=rsc.PAYLOAD_BUDGET_SEC)
    parser.add_argument("--finalization-alloc-sec", type=float, default=rsc.FINALIZATION_ALLOC_SEC)
    parser.add_argument("--driver-limit-sec", type=float, default=rsc.DRIVER_LIMIT_SEC)
    parser.add_argument("--grace-sec", type=float, default=rsc.GRACE_SEC)
    parser.add_argument("--min-disk-gib", type=float, default=rsc.MIN_DISK_GIB)
    parser.add_argument("--ipc-req-fd", type=int)
    parser.add_argument("--ipc-ack-fd", type=int)
    for name in ("p-sha", "w-sha", "c-sha", "repository", "run-id", "run-attempt", "job-id", "job-key", "invocation-id"):
        parser.add_argument("--" + name)
    parser.add_argument("--publisher-timeout-sec", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.mode != "validation-only":
        print("AUTH_REFUSED: synthetic wrapper cannot execute strict mode", file=sys.stderr)
        return rsc.AUTH_REFUSED_EXIT_CODE

    actual = (revision(args.p), revision(args.w), revision(REPO_ROOT))
    expected = (args.p_sha, args.w_sha, args.c_sha)
    if any(not exp or exp != got for got, exp in zip(actual, expected)):
        print("source revision mismatch", file=sys.stderr)
        return 1
    data_dir = os.path.realpath(args.case_data_dir)
    for root in (args.p, args.w, REPO_ROOT):
        if os.path.commonpath((data_dir, os.path.realpath(root))) == os.path.realpath(root):
            raise ValueError("case data must be outside source checkouts")
    os.makedirs(data_dir, exist_ok=True)
    drivers = canonical_drivers(args.w) + ["synthetic_exclusion_addition", "synthetic_artifact_addition"]
    config = {"c_sha": actual[2], "required_drivers": drivers}
    if args.case == "failed-plan":
        config["plan"] = {"exit_code": 7}
    elif args.case == "failed-pin":
        config["pin"] = {"omit_pin": True, "exit_code": 9}
    elif args.case == "divergence":
        payload = os.urandom(64)
        with open(os.path.join(data_dir, "divergence.bin"), "wb") as f:
            f.write(payload)
        config["run3/" + drivers[0]] = {"exit_code": 11, "status": "FAIL", "reasons": ["synthetic divergence"], "divergence_hex": payload.hex()}
    elif args.case == "cleanup-failure":
        config["run1"] = {"inject_eligible_symlink": True, "symlink_target": data_dir}
    elif args.case == "ownership-crash":
        config["plan"] = {
            "spawn_nested": True,
            "sleep": 600,
            "flush_delay": 1,
            "completion_marker": os.path.join(data_dir, "ownership-flushed"),
            "ready_file": os.path.join(data_dir, "ownership-ready"),
            "pid_file": os.path.join(data_dir, "ownership-pids"),
        }
    with tempfile.TemporaryDirectory(prefix="strict-val-", dir=data_dir) as temp:
        emitter = os.path.join(temp, "synthetic_run_proof.py")
        emitter_bytes = FAKE_STAGE_EMITTER_SOURCE.encode("utf-8")
        with open(emitter, "wb") as f:
            f.write(emitter_bytes)
        os.chmod(emitter, stat.S_IRWXU)
        config_path = os.path.join(temp, "config.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f)
        old_config = os.environ.get("FAKE_STAGE_CONFIG")
        os.environ["FAKE_STAGE_CONFIG"] = config_path
        try:
            controller = rsc.RemoteStrictController(
                p_path=args.p, w_path=args.w, compiler_path=args.compiler,
                artifacts_dir=args.artifacts_dir, run_proof_py=emitter,
                fixture_sha256=hashlib.sha256(emitter_bytes).hexdigest(),
                job_start_time=args.job_start_time, host_job_limit_sec=args.host_job_limit_sec,
                payload_budget_sec=args.payload_budget_sec, finalization_alloc_sec=args.finalization_alloc_sec,
                driver_limit_sec=args.driver_limit_sec, grace_sec=args.grace_sec,
                min_disk_gib=args.min_disk_gib, mode="validation-only",
                ipc_req_fd=args.ipc_req_fd, ipc_ack_fd=args.ipc_ack_fd,
                p_sha=args.p_sha, w_sha=args.w_sha, c_sha=args.c_sha,
                repository=args.repository, run_id=args.run_id, run_attempt=args.run_attempt,
                job_id=args.job_id, job_key=args.job_key, invocation_id=args.invocation_id,
                publisher_timeout_sec=args.publisher_timeout_sec,
            )
            return controller.run()
        finally:
            if old_config is None:
                os.environ.pop("FAKE_STAGE_CONFIG", None)
            else:
                os.environ["FAKE_STAGE_CONFIG"] = old_config


if __name__ == "__main__":
    sys.exit(main())
