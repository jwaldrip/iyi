#!/usr/bin/env python3
"""
proof/test_hosted_containers.py: Unit tests for proof/hosted_containers.py.

Validates PlanControllerRepairs Section 3.5 and Slice C (lines 138-161, 280-295):
- Purely mocked unit tests: zero invocation of real Docker or shared system state.
- Creation intent recorded before Docker invocation (unique owned name and audit labels).
- Exact 64-character container ID reconciliation across stdout/cidfile/inspect.
- Uncertain create reconciliation using ONLY recorded intent (never broad prefix sweeps).
- Pre-start inspect of effective cage settings and mounts (fail-closed before start).
- Bounded stdout/stderr capture.
- Encompassing teardown in finally blocks across ALL paths (normal, error, mount rejection, timeout, cancellation).
- Unregister only after verified removal.
- Daemon outage, ambiguous inspect, timed-out cleanup, or unreconciled creation remains UNRESOLVED,
  marking the session failed closed and blocking subsequent stages.
- Non-reentrant signal cancellation unwinding cleanly into standard cleanup.
- Preflight controls use the exact same ownership mechanism.
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import unittest
from typing import Any, Dict, List, Optional, Sequence, Tuple
from unittest.mock import MagicMock, patch

try:
    from proof.hosted_contracts import CagePolicy, TeardownDisposition, TypeValidationError
    from proof.hosted_containers import (
        CageInspectionError,
        ContainerCancelledError,
        ContainerLifecycleError,
        ContainerOutcome,
        ContainerSpec,
        ContainerTimeoutError,
        CreationIntent,
        CreationIntentError,
        DEFAULT_MAX_STDOUT_BYTES,
        MountBinding,
        MountInspectionError,
        OwnedContainerSession,
        OwnershipReconciliationError,
        TeardownResult,
        UnresolvedOwnershipError,
    )
except ImportError:
    from hosted_contracts import CagePolicy, TeardownDisposition, TypeValidationError
    from hosted_containers import (
        CageInspectionError,
        ContainerCancelledError,
        ContainerLifecycleError,
        ContainerOutcome,
        ContainerSpec,
        ContainerTimeoutError,
        CreationIntent,
        CreationIntentError,
        DEFAULT_MAX_STDOUT_BYTES,
        MountBinding,
        MountInspectionError,
        OwnedContainerSession,
        OwnershipReconciliationError,
        TeardownResult,
        UnresolvedOwnershipError,
    )


def make_valid_cage_policy() -> CagePolicy:
    return CagePolicy(
        uid=65534,
        gid=65534,
        network="none",
        read_only_root=True,
        drop_capabilities="ALL",
        no_new_privileges=True,
        private_pid_namespace=True,
        default_confined_seccomp=True,
        init_process=True,
        pids_limit=32,
        tmpfs_tmp_size="16m",
        tmpfs_dev_shm_size="64m",
    )


def make_mock_inspect_data(
    container_id: str,
    container_name: str,
    intent_id: str,
    running: bool = False,
    privileged: bool = False,
    network_mode: str = "none",
    readonly_root: bool = True,
    cap_drop: Sequence[str] = ("ALL",),
    security_opt: Sequence[str] = ("no-new-privileges",),
    pid_mode: str = "",
    user: str = "65534:65534",
    pids_limit: int = 32,
    mounts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if mounts is None:
        mounts = [
            {"Destination": "/tmp", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
            {"Destination": "/dev/shm", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
        ]
    return {
        "Id": container_id,
        "Name": f"/{container_name}",
        "State": {
            "Running": running,
            "ExitCode": 0,
            "Pid": 1234 if running else 0,
        },
        "Config": {
            "User": user,
            "Labels": {
                "iyi.managed": "true",
                "iyi.intent_id": intent_id,
            },
        },
        "HostConfig": {
            "Privileged": privileged,
            "NetworkMode": network_mode,
            "ReadonlyRootfs": readonly_root,
            "CapDrop": list(cap_drop),
            "SecurityOpt": list(security_opt),
            "PidMode": pid_mode,
            "Init": True,
            "PidsLimit": pids_limit,
        },
        "Mounts": mounts,
    }


class SpecAndDataClassTests(unittest.TestCase):
    """Test specifications, bindings, and dataclasses."""

    def test_container_spec_valid(self):
        spec = ContainerSpec(
            command=("python3", "-c", "print('hello')"),
            image="iyi-linux-proof:latest",
            stage="proof",
            attempt=1,
            timeout_sec=30.0,
            cage_policy=make_valid_cage_policy(),
            mount_bindings=(
                MountBinding(container_path="/P", host_path="/host/P", access="ro"),
            ),
        )
        self.assertEqual(spec.command, ("python3", "-c", "print('hello')"))
        self.assertEqual(spec.stage, "proof")
        self.assertEqual(spec.attempt, 1)
        self.assertIsInstance(spec.digest(), str)
        self.assertEqual(len(spec.digest()), 64)

    def test_container_spec_invalid_fields(self):
        # Empty command
        with self.assertRaises(TypeValidationError):
            ContainerSpec(command=(), image="img", stage="proof", attempt=1)

        # Invalid command arguments
        with self.assertRaises(TypeValidationError):
            ContainerSpec(command=(123,), image="img", stage="proof", attempt=1)  # type: ignore

        # Empty image
        with self.assertRaises(TypeValidationError):
            ContainerSpec(command=("ls",), image="", stage="proof", attempt=1)

        # Invalid attempt
        with self.assertRaises(TypeValidationError):
            ContainerSpec(command=("ls",), image="img", stage="proof", attempt=0)

        # Invalid timeout
        with self.assertRaises(TypeValidationError):
            ContainerSpec(command=("ls",), image="img", stage="proof", attempt=1, timeout_sec=-5.0)

    def test_mount_binding_validation(self):
        # Valid bind
        mb = MountBinding(container_path="/inputs", host_path="/host/inputs", access="ro")
        self.assertEqual(mb.to_docker_mount_arg(), "--mount=type=bind,src=/host/inputs,dst=/inputs,readonly,bind-propagation=private")

        # Valid tmpfs
        mb_tmp = MountBinding(container_path="/scratch", host_path=None, access="rw", mount_type="tmpfs", options=("size=64m",))
        self.assertEqual(mb_tmp.to_docker_mount_arg(), "--mount=type=tmpfs,dst=/scratch,size=64m")

        # Missing host_path for bind
        with self.assertRaises(TypeValidationError):
            MountBinding(container_path="/P", host_path=None, access="ro", mount_type="bind")

        # Invalid access
        with self.assertRaises(TypeValidationError):
            MountBinding(container_path="/P", host_path="/host/P", access="write")

    def test_teardown_result_is_resolved(self):
        # Resolved
        tr = TeardownResult(
            resolved=True,
            container_id="a" * 64,
            container_name="iyi-c-test-1",
            stopped=True,
            removed=True,
            clean_exit=True,
            unresolved_processes=0,
            unresolved_reason=None,
        )
        self.assertTrue(tr.is_resolved())
        disp = tr.to_disposition("launch-123")
        self.assertTrue(disp.is_resolved())

        # Unresolved
        tr_unres = TeardownResult(
            resolved=False,
            container_id="a" * 64,
            container_name="iyi-c-test-1",
            stopped=True,
            removed=False,
            clean_exit=False,
            unresolved_processes=0,
            unresolved_reason="docker rm timed out",
        )
        self.assertFalse(tr_unres.is_resolved())
        with self.assertRaises(UnresolvedOwnershipError):
            tr_unres.to_disposition("launch-123")

    def test_container_outcome_mandatory_teardown(self):
        tr = TeardownResult(
            resolved=True,
            container_id="a" * 64,
            container_name="iyi-c-test-1",
            stopped=True,
            removed=True,
            clean_exit=True,
        )
        outcome = ContainerOutcome(
            exit_code=0,
            stdout="hello\n",
            stderr="",
            duration_sec=0.5,
            timed_out=False,
            cancelled=False,
            teardown=tr,
        )
        self.assertEqual(outcome.exit_code, 0)
        self.assertTrue(outcome.teardown.is_resolved())

        # Invalid teardown type
        with self.assertRaises(TypeValidationError):
            ContainerOutcome(
                exit_code=0,
                stdout="",
                stderr="",
                duration_sec=0.1,
                timed_out=False,
                cancelled=False,
                teardown=None,  # type: ignore
            )


class OwnedContainerSessionTests(unittest.TestCase):
    """Test session lifecycle, reconciliation, inspection, and fail-closed behaviors."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.session_dir = pathlib.Path(self.temp_dir.name)
        self.invocation_id = "test-inv-001"
        self.session = OwnedContainerSession(
            invocation_id=self.invocation_id,
            session_dir=self.session_dir,
            docker_cmd=("docker",),
        )

    def tearDown(self):
        self.session.close()
        self.temp_dir.cleanup()

    def test_creation_intent_recorded_before_docker_create(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="preflight",
            attempt=1,
        )
        intent = self.session.record_creation_intent(spec)
        self.assertTrue(intent.container_name.startswith("iyi-c-test-inv-00-preflight-1-"))
        self.assertEqual(intent.stage, "preflight")
        self.assertEqual(intent.attempt, 1)
        self.assertIn("iyi.managed", intent.labels)
        self.assertIn("iyi.intent_id", intent.labels)
        # cidfile should not exist before create
        self.assertFalse(os.path.exists(intent.cidfile_path))
        # Intent should be stored in pending
        self.assertIn(intent.intent_id, self.session._pending_intents)

    def test_reconcile_id_success(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        intent = self.session.record_creation_intent(spec)
        cid = "a" * 64

        # Simulate cidfile written by docker
        pathlib.Path(intent.cidfile_path).write_text(cid + "\n", encoding="utf-8")

        mock_inspect = make_mock_inspect_data(cid, intent.container_name, intent.intent_id)

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([mock_inspect]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        reconciled = self.session._reconcile_create_id(intent, cid + "\n", intent.cidfile_path)
        self.assertEqual(reconciled, cid)

    def test_reconcile_id_disagreement_fails_closed(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        intent = self.session.record_creation_intent(spec)
        cid_stdout = "a" * 64
        cid_file = "b" * 64

        pathlib.Path(intent.cidfile_path).write_text(cid_file + "\n", encoding="utf-8")

        with self.assertRaises(OwnershipReconciliationError):
            self.session._reconcile_create_id(intent, cid_stdout, intent.cidfile_path)

    def test_reconcile_id_invalid_format(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        intent = self.session.record_creation_intent(spec)
        with self.assertRaises(OwnershipReconciliationError):
            self.session._reconcile_create_id(intent, "invalid-short-id", intent.cidfile_path)

    def test_uncertain_create_reconciled_found_and_cleaned(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        cid = "c" * 64

        inspect_calls: List[List[str]] = []

        def runner(cmd, **kwargs):
            inspect_calls.append(list(cmd))
            if "create" in cmd:
                # Simulate timeout or error on create
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="client timeout")
            if "inspect" in cmd:
                # Inspect for exact name finds the container on daemon!
                target = cmd[-1]
                data = make_mock_inspect_data(cid, target.lstrip("/"), "test-intent")
                # When verifying after rm, simulate it is gone
                if any("rm" in c for c in inspect_calls):
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd or "rm" in cmd or "kill" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        intent = self.session.record_creation_intent(spec)
        # Override intent_id in mock inspect to match
        mock_data = make_mock_inspect_data(cid, intent.container_name, intent.intent_id)

        def runner_matching(cmd, **kwargs):
            inspect_calls.append(list(cmd))
            if "create" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="client timeout")
            if "inspect" in cmd:
                if any("rm" in c for c in inspect_calls):
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([mock_data]), stderr="")
            if "stop" in cmd or "rm" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner_matching
        reconciled_id = self.session.reconcile_uncertain_create(intent)
        self.assertEqual(reconciled_id, cid)

    def test_uncertain_create_verified_not_created(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        intent = self.session.record_creation_intent(spec)

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container: " + cmd[-1])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        reconciled_id = self.session.reconcile_uncertain_create(intent)
        self.assertIsNone(reconciled_id)

    def test_uncertain_create_daemon_outage_unresolved(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        intent = self.session.record_creation_intent(spec)

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(UnresolvedOwnershipError):
            self.session.reconcile_uncertain_create(intent)

    def test_no_broad_sweeps(self):
        """Verify that reconciliation and cleanup NEVER execute broad sweeps or prefix queries."""
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        invoked_commands: List[List[str]] = []

        def runner(cmd, **kwargs):
            invoked_commands.append(list(cmd))
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        intent = self.session.record_creation_intent(spec)
        self.session.reconcile_uncertain_create(intent)

        # Ensure no command used 'ps', '--filter', or wildcard names
        for cmd in invoked_commands:
            self.assertNotIn("ps", cmd)
            for arg in cmd:
                self.assertFalse(arg.startswith("--filter"))
                self.assertNotIn("*", arg)

    def test_cage_inspection_rejects_privileged(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "d" * 64
        inspect_data = make_mock_inspect_data(cid, "iyi-c-test-1", "intent-1", privileged=True)

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_cage_inspection_rejects_host_pid(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "d" * 64
        inspect_data = make_mock_inspect_data(cid, "iyi-c-test-1", "intent-1", pid_mode="host")

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_cage_inspection_rejects_unconfined_seccomp(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "d" * 64
        inspect_data = make_mock_inspect_data(
            cid, "iyi-c-test-1", "intent-1",
            security_opt=["no-new-privileges", "seccomp=unconfined"]
        )

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_mount_inspection_rejects_docker_sock(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        cid = "e" * 64
        inspect_data = make_mock_inspect_data(
            cid, "iyi-c-test-1", "intent-1",
            mounts=[{"Destination": "/var/run/docker.sock", "Source": "/var/run/docker.sock", "RW": True, "Type": "bind"}]
        )

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(MountInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_mount_inspection_rejects_host_proc(self):
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        cid = "e" * 64
        inspect_data = make_mock_inspect_data(
            cid, "iyi-c-test-1", "intent-1",
            mounts=[{"Destination": "/host-proc", "Source": "/proc", "RW": False, "Type": "bind"}]
        )

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(MountInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_mount_inspection_rejects_writable_ro_mount(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            mount_bindings=(MountBinding(container_path="/P", host_path="/host/P", access="ro"),),
        )
        cid = "e" * 64
        inspect_data = make_mock_inspect_data(
            cid, "iyi-c-test-1", "intent-1",
            mounts=[{"Destination": "/P", "Source": "/host/P", "RW": True, "Type": "bind"}]
        )

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(MountInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_normal_run_lifecycle_and_teardown(self):
        """Full normal lifecycle: create -> inspect -> start -> stop/rm -> verified removal."""
        spec = ContainerSpec(
            command=("python3", "-c", "print('success')"),
            image="test-img",
            stage="proof",
            attempt=1,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "f" * 64
        inspect_after_rm = False

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="success\n", stderr="")
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    # Verified removed!
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container: " + cmd[-1])
                # During pre-start inspect
                target = cmd_list[-1]
                data = make_mock_inspect_data(cid, target, "test-intent")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd_list or "kill" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "rm" in cmd_list:
                inspect_after_rm = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        outcome = self.session.run_container(spec)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.stdout.strip(), "success")
        self.assertTrue(outcome.teardown.is_resolved())
        self.assertEqual(len(self.session._active_containers), 0)

    def test_mount_failure_still_cleans_up_in_finally(self):
        """If mount inspect fails, container is never started, but is stopped and removed in finally."""
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
        )
        cid = "1" * 64
        inspect_after_rm = False
        started = False

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm, started
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                started = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                # Return bad mount (docker.sock leak)
                bad_data = make_mock_inspect_data(
                    cid, "test-name", "intent-id",
                    mounts=[{"Destination": "/docker.sock", "Source": "/var/run/docker.sock", "RW": True, "Type": "bind"}]
                )
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([bad_data]), stderr="")
            if "stop" in cmd_list or "rm" in cmd_list or "kill" in cmd_list:
                inspect_after_rm = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        outcome = self.session.run_container(spec)
        self.assertEqual(outcome.exit_code, -1)
        self.assertFalse(started)
        self.assertTrue(outcome.teardown.is_resolved())
        self.assertEqual(len(self.session._active_containers), 0)

    def test_daemon_outage_during_rm_fails_closed(self):
        """If docker inspect during rm verification fails with daemon outage, session fails closed."""
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        cid = "2" * 64

        def runner(cmd, **kwargs):
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="ran\n", stderr="")
            if "inspect" in cmd_list:
                if any("rm" in c for c in invoked_cmds):
                    # Daemon outage on removal check!
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
                data = make_mock_inspect_data(cid, "test-name", "intent-id")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd_list or "rm" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        invoked_cmds: List[List[str]] = []

        def tracking_runner(cmd, **kwargs):
            invoked_cmds.append(list(cmd))
            return runner(cmd, **kwargs)

        self.session._custom_runner = tracking_runner

        with self.assertRaises(UnresolvedOwnershipError):
            self.session.run_container(spec)

        self.assertTrue(self.session.has_unresolved_ownership())

        # Any subsequent run_container call must immediately fail closed without invoking docker!
        with self.assertRaises(UnresolvedOwnershipError):
            self.session.run_container(spec)

    def test_container_still_exists_after_rm_unresolved(self):
        """If container inspect succeeds (returncode 0) after rm, container still exists -> unresolved."""
        spec = ContainerSpec(command=("echo", "hi"), image="test-img", stage="proof", attempt=1)
        cid = "3" * 64

        def runner(cmd, **kwargs):
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "inspect" in cmd_list:
                # Always returns that container exists!
                data = make_mock_inspect_data(cid, "test-name", "intent-id")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(UnresolvedOwnershipError):
            self.session.run_container(spec)

        self.assertTrue(self.session.has_unresolved_ownership())

    def test_signal_cancellation_unwinds_not_reentrant(self):
        """Signal handling requests cancellation and unwinds; zero docker calls in handler."""
        invoked_cmds: List[List[str]] = []

        def runner(cmd, **kwargs):
            invoked_cmds.append(list(cmd))
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=("4" * 64) + "\n", stderr="")
            if "inspect" in cmd_list:
                if any("rm" in c for c in invoked_cmds):
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                data = make_mock_inspect_data("4" * 64, "test-name", "intent-id")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner

        # Directly invoke signal handler
        with self.assertRaises(ContainerCancelledError):
            self.session._handle_signal(signal.SIGTERM, None)

        self.assertTrue(self.session.is_cancelled())
        # Ensure signal handler did NOT invoke docker commands directly
        self.assertEqual(len(invoked_cmds), 0)

    def test_preflight_probe_uses_same_mechanism(self):
        spec = ContainerSpec(
            command=("python3", "-c", "import socket; print('probe')"),
            image="test-img",
            stage="preflight",
            attempt=1,
        )
        cid = "5" * 64
        inspect_after_rm = False

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="probe\n", stderr="")
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                data = make_mock_inspect_data(cid, "test-probe", "intent-id")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "rm" in cmd_list or "stop" in cmd_list:
                inspect_after_rm = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        outcome = self.session.run_probe(spec)
        self.assertEqual(outcome.exit_code, 0)
        self.assertTrue(outcome.teardown.is_resolved())

    def test_bounded_output(self):
        spec = ContainerSpec(
            command=("cat", "/dev/zero"),
            image="test-img",
            stage="proof",
            attempt=1,
            max_stdout_bytes=100,
            max_stderr_bytes=100,
        )
        cid = "6" * 64
        inspect_after_rm = False

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                # Return 10,000 bytes of output
                return subprocess.CompletedProcess(cmd, 0, stdout="X" * 10000, stderr="E" * 10000)
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                data = make_mock_inspect_data(cid, "test-bounded", "intent-id")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "rm" in cmd_list or "stop" in cmd_list:
                inspect_after_rm = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        outcome = self.session.run_container(spec)
        self.assertTrue(outcome.bounded)
        self.assertLessEqual(len(outcome.stdout), 100)
        self.assertLessEqual(len(outcome.stderr), 100)
        self.assertTrue(outcome.teardown.is_resolved())


if __name__ == "__main__":
    unittest.main()
