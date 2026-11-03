#!/usr/bin/env python3
"""
Validation-only wrapper for hosted Strict Supervisor Action execution.

Prepares the shared synthetic fixture environment with canonical W modules
and invokes RemoteStrictController in validation-only mode.
Real strict mode is unconditionally refused with exit code 5 (AUTH_REFUSED).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
import tempfile
from typing import Sequence

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import proof.remote_strict_controller as rsc
from proof.remote_strict_fixtures import (
    FAKE_STAGE_EMITTER_SOURCE,
    provision_canonical_w,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Remote Strict Validation Wrapper")
    parser.add_argument("--mode", default="validation-only", help="Execution mode")
    parser.add_argument("--p", required=True, help="Path to clean P source checkout")
    parser.add_argument("--w", required=True, help="Path to clean W audited proof checkout")
    parser.add_argument("--compiler", required=True, help="Path to compiler binary or dummy compiler")
    parser.add_argument("--artifacts-dir", default="strict-proof-artifacts", help="Path to controller artifacts dir")
    parser.add_argument("--job-start-time", default=None, help="Job start time")
    parser.add_argument("--host-job-limit-sec", type=float, default=rsc.HOST_JOB_LIMIT_SEC)
    parser.add_argument("--payload-budget-sec", type=float, default=rsc.PAYLOAD_BUDGET_SEC)
    parser.add_argument("--finalization-alloc-sec", type=float, default=rsc.FINALIZATION_ALLOC_SEC)
    parser.add_argument("--driver-limit-sec", type=float, default=rsc.DRIVER_LIMIT_SEC)
    parser.add_argument("--grace-sec", type=float, default=rsc.GRACE_SEC)
    parser.add_argument("--min-disk-gib", type=float, default=rsc.MIN_DISK_GIB)
    parser.add_argument("--ipc-req-fd", type=int, default=None)
    parser.add_argument("--ipc-ack-fd", type=int, default=None)
    parser.add_argument("--p-sha", default=None)
    parser.add_argument("--w-sha", default=None)
    parser.add_argument("--c-sha", default=None)
    parser.add_argument("--repository", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--run-attempt", default=None)
    parser.add_argument("--job-id", default=None)
    parser.add_argument("--publisher-timeout-sec", type=float, default=30.0)

    args, unknown = parser.parse_known_args(argv)

    # 1. Unconditional refusal if strict mode is requested in this wrapper
    if args.mode == "strict":
        print(
            "STRICT_MODE_AUTH_REFUSED: Strict execution mode requested in validation-only wrapper. "
            "Refusing execution with exit 5 (AUTH_REFUSED).",
            file=sys.stderr,
        )
        return rsc.AUTH_REFUSED_EXIT_CODE

    # 2. Provision canonical modules under W proof directory
    try:
        canonical_src = os.path.dirname(os.path.abspath(__file__))
        provision_canonical_w(args.w, source_proof_dir=canonical_src)
    except Exception as exc:
        print(f"ERROR: Failed to provision canonical W proof modules: {exc}", file=sys.stderr)
        return 1

    # 3. Create synthetic stage emitter outside W
    synthetic_emitter_dir = tempfile.mkdtemp(prefix="strict-val-emitter-")
    synthetic_run_proof = os.path.join(synthetic_emitter_dir, "synthetic_run_proof.py")
    with open(synthetic_run_proof, "w", encoding="utf-8") as f:
        f.write(FAKE_STAGE_EMITTER_SOURCE)
    os.chmod(synthetic_run_proof, stat.S_IRWXU)

    # 4. Invoke RemoteStrictController in validation-only mode
    controller = rsc.RemoteStrictController(
        p_path=args.p,
        w_path=args.w,
        compiler_path=args.compiler,
        artifacts_dir=args.artifacts_dir,
        run_proof_py=synthetic_run_proof,
        job_start_time=args.job_start_time,
        host_job_limit_sec=args.host_job_limit_sec,
        payload_budget_sec=args.payload_budget_sec,
        finalization_alloc_sec=args.finalization_alloc_sec,
        driver_limit_sec=args.driver_limit_sec,
        grace_sec=args.grace_sec,
        min_disk_gib=args.min_disk_gib,
        mode="validation-only",
        ipc_req_fd=args.ipc_req_fd,
        ipc_ack_fd=args.ipc_ack_fd,
        p_sha=args.p_sha,
        w_sha=args.w_sha,
        c_sha=args.c_sha,
        repository=args.repository,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        job_id=args.job_id,
        publisher_timeout_sec=args.publisher_timeout_sec,
    )

    try:
        return controller.run()
    finally:
        shutil.rmtree(synthetic_emitter_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
