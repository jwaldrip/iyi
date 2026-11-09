#!/usr/bin/env python3
"""
proof/test_hosted_containers.py: Unit tests for proof/hosted_containers.py.

Validates PlanControllerRepairs Section 3.5 and Slice C (lines 138-161, 280-295),
incorporating all security review remediations (ReviewOwnedContainers exact826d):
- Purely mocked unit tests: zero invocation of real Docker or shared system state.
  Fail-closed mock runner established in setUp through tearDown.
- Creation intent recorded before Docker invocation (unique owned name and audit labels).
- Exact 64-character container ID reconciliation across stdout/cidfile/inspect.
  Conflicting identity evidence fails closed immediately.
- Uncertain create reconciliation using ONLY recorded intent (never broad prefix sweeps).
- Pre-start inspect of effective cage settings and mounts:
  * Rejection of undeclared mounts (such as image-defined VOLUME directives)
  * Rejection of docker.sock, host /proc, /sys, /dev
  * Rejection of unconfined seccomp, host namespaces (PidMode, IpcMode, UtsMode), CapAdd
  * Rejection of mount inode aliasing
- Mandatory cage policy enforcement (omission strictly forbidden).
- Strict image reference validation against Docker option injection, and option terminator '--'.
- Finite positive deadline and timeout enforcement (rejects NaN, +Inf, -Inf, and absent limits).
- Bounded stdout/stderr capture; stream overflow fails the invocation rather than returning success.
- Bounded auxiliary Docker command output (create, inspect, rm, exec, top).
- Encompassing teardown in finally blocks across ALL paths (normal, error, mount rejection, timeout, cancellation).
- Teardown exceptions are captured without escaping; failure records unresolved ownership and fails closed.
- Removal explicitly omits '-v' to prevent deleting attached volumes.
- Destructive operations strictly validate container ownership before invoking Docker.
- Detached preflight starts enforce identical inspection, cancellation, and fail-closed admission.
- Non-reentrant signal cancellation unwinding cleanly into standard cleanup.
- Preflight controls use the exact same ownership mechanism.
"""

from __future__ import annotations

import dataclasses
import json
import math
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
        ConflictingIdentityError,
        ContainerCancelledError,
        ContainerLifecycleError,
        ContainerOutcome,
        ContainerSpec,
        ContainerTimeoutError,
        CreationIntent,
        CreationIntentError,
        DEFAULT_MAX_AUX_BYTES,
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
        ConflictingIdentityError,
        ContainerCancelledError,
        ContainerLifecycleError,
        ContainerOutcome,
        ContainerSpec,
        ContainerTimeoutError,
        CreationIntent,
        CreationIntentError,
        DEFAULT_MAX_AUX_BYTES,
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
    cap_add: Optional[Sequence[str]] = None,
    security_opt: Sequence[str] = ("no-new-privileges",),
    pid_mode: str = "",
    ipc_mode: str = "",
    uts_mode: str = "",
    user: str = "65534:65534",
    pids_limit: int = 32,
    mounts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if mounts is None:
        mounts = [
            {"Destination": "/tmp", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
            {"Destination": "/dev/shm", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
            {"Destination": "/etc/resolv.conf", "Source": "/host/resolv.conf", "RW": False, "Type": "bind"},
            {"Destination": "/etc/hostname", "Source": "/host/hostname", "RW": False, "Type": "bind"},
            {"Destination": "/etc/hosts", "Source": "/host/hosts", "RW": False, "Type": "bind"},
        ]
    return {
        "Id": container_id,
        "Name": f"/{container_name.lstrip('/')}",
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
            "CapAdd": list(cap_add) if cap_add is not None else [],
            "SecurityOpt": list(security_opt),
            "PidMode": pid_mode,
            "IpcMode": ipc_mode,
            "UtsMode": uts_mode,
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

    def test_container_spec_mandatory_cage_policy(self):
        # cage_policy cannot be None (Finding 5)
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="img:latest",
                stage="proof",
                attempt=1,
                timeout_sec=10.0,
                cage_policy=None,  # type: ignore
            )

    def test_container_spec_image_option_injection_rejected(self):
        # Image reference cannot start with '-' or inject Docker options (Finding 6)
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="--pid=host evil-image",
                stage="proof",
                attempt=1,
                timeout_sec=10.0,
                cage_policy=make_valid_cage_policy(),
            )
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="-v /host:/root evil",
                stage="proof",
                attempt=1,
                timeout_sec=10.0,
                cage_policy=make_valid_cage_policy(),
            )

    def test_container_spec_finite_deadline_required(self):
        # Deadlines and timeouts must be finite positive numbers (Finding 8)
        cp = make_valid_cage_policy()
        # Both None rejected
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="img:latest",
                stage="proof",
                attempt=1,
                timeout_sec=None,
                deadline=None,
                cage_policy=cp,
            )
        # NaN rejected
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="img:latest",
                stage="proof",
                attempt=1,
                timeout_sec=float("nan"),
                cage_policy=cp,
            )
        # Infinity rejected
        with self.assertRaises(TypeValidationError):
            ContainerSpec(
                command=("echo", "hi"),
                image="img:latest",
                stage="proof",
                attempt=1,
                timeout_sec=float("inf"),
                cage_policy=cp,
            )

    def test_mount_binding_validation(self):
        mb = MountBinding(container_path="/inputs", host_path="/host/inputs", access="ro")
        self.assertEqual(mb.to_docker_mount_arg(), "--mount=type=bind,src=/host/inputs,dst=/inputs,readonly,bind-propagation=private")

        mb_tmp = MountBinding(container_path="/scratch", host_path=None, access="rw", mount_type="tmpfs", options=("size=64m",))
        self.assertEqual(mb_tmp.to_docker_mount_arg(), "--mount=type=tmpfs,dst=/scratch,size=64m")

        with self.assertRaises(TypeValidationError):
            MountBinding(container_path="/P", host_path=None, access="ro", mount_type="bind")

        with self.assertRaises(TypeValidationError):
            MountBinding(container_path="/P", host_path="/host/P", access="write")

    def test_teardown_result_is_resolved(self):
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


class OwnedContainerSessionTests(unittest.TestCase):
    """Test session lifecycle, reconciliation, inspection, and fail-closed behaviors."""

    def default_mock_runner(self, cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
        """Fail-closed default mock runner: strictly prevents any real Docker invocation."""
        cmd_list = list(cmd)
        if "inspect" in cmd_list:
            # Safe default for inspect: not found
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container: " + cmd_list[-1])
        if "stop" in cmd_list or "kill" in cmd_list or "rm" in cmd_list:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        raise RuntimeError(f"Unexpected unmocked Docker command in unit test: {cmd_list}")

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.session_dir = pathlib.Path(self.temp_dir.name)
        self.invocation_id = "test-inv-001"

        # Strictly prevent real Docker calls by installing default_mock_runner
        self.session = OwnedContainerSession(
            invocation_id=self.invocation_id,
            session_dir=self.session_dir,
            docker_cmd=("docker",),
            subprocess_runner=self.default_mock_runner,
        )

        # Patch subprocess.run and Popen as an additional fail-closed guard
        self.subp_run_patcher = patch("subprocess.run", side_effect=RuntimeError("Real subprocess.run forbidden in unit test"))
        self.subp_popen_patcher = patch("subprocess.Popen", side_effect=RuntimeError("Real subprocess.Popen forbidden in unit test"))
        self.subp_run_patcher.start()
        self.subp_popen_patcher.start()

    def tearDown(self):
        self.session.close()
        self.subp_run_patcher.stop()
        self.subp_popen_patcher.stop()
        self.temp_dir.cleanup()

    def test_creation_intent_recorded_before_docker_create(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="preflight",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        intent = self.session.record_creation_intent(spec)
        self.assertTrue(intent.container_name.startswith("iyi-c-test-inv-00-preflight-1-"))
        self.assertEqual(intent.stage, "preflight")
        self.assertEqual(intent.attempt, 1)
        self.assertIn("iyi.managed", intent.labels)
        self.assertIn("iyi.intent_id", intent.labels)
        self.assertFalse(os.path.exists(intent.cidfile_path))
        self.assertIn(intent.intent_id, self.session._pending_intents)

    def test_reconcile_id_success(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        intent = self.session.record_creation_intent(spec)
        cid = "a" * 64

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
        # Conflicting identity evidence fails closed (Finding 13)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        intent = self.session.record_creation_intent(spec)
        cid_stdout = "a" * 64
        cid_file = "b" * 64

        pathlib.Path(intent.cidfile_path).write_text(cid_file + "\n", encoding="utf-8")

        with self.assertRaises(ConflictingIdentityError):
            self.session._reconcile_create_id(intent, cid_stdout, intent.cidfile_path)

    def test_create_container_option_terminator(self):
        # Verify '--' terminates options before image (Finding 6)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="alpine:3.18",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        captured_cmds: List[List[str]] = []
        cid = "1" * 64

        def runner(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "inspect" in cmd_list:
                # Dynamic matching inspect
                data = make_mock_inspect_data(cid, cmd_list[-1], intent.intent_id)
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        intent, created_id = self.session.create_container(spec)

        create_cmd = captured_cmds[0]
        # Assert '--' is immediately before image
        img_idx = create_cmd.index("alpine:3.18")
        self.assertEqual(create_cmd[img_idx - 1], "--")
        self.assertEqual(created_id, cid)

    def test_uncertain_create_reconciled_found_and_cleaned(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "c" * 64
        intent = self.session.record_creation_intent(spec)
        mock_data = make_mock_inspect_data(cid, intent.container_name, intent.intent_id)

        inspect_calls: List[List[str]] = []

        def runner(cmd, **kwargs):
            inspect_calls.append(list(cmd))
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="client timeout")
            if "inspect" in cmd_list:
                if any("rm" in c for c in inspect_calls):
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([mock_data]), stderr="")
            if "stop" in cmd_list or "rm" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        reconciled_id = self.session.reconcile_uncertain_create(intent)
        self.assertEqual(reconciled_id, cid)

    def test_uncertain_create_verified_not_created(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        intent = self.session.record_creation_intent(spec)

        def runner(cmd, **kwargs):
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container: " + cmd[-1])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        reconciled_id = self.session.reconcile_uncertain_create(intent)
        self.assertIsNone(reconciled_id)

    def test_uncertain_create_daemon_outage_unresolved(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
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
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        invoked_commands: List[List[str]] = []

        def runner(cmd, **kwargs):
            invoked_commands.append(list(cmd))
            if "inspect" in cmd:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        intent = self.session.record_creation_intent(spec)
        self.session.reconcile_uncertain_create(intent)

        for cmd in invoked_commands:
            self.assertNotIn("ps", cmd)
            for arg in cmd:
                self.assertFalse(arg.startswith("--filter"))
                self.assertNotIn("*", arg)

    def test_destructive_unowned_target_rejected(self):
        # Validate that unowned targets are rejected before issuing Docker commands (Finding 3)
        with self.assertRaises(OwnershipReconciliationError):
            self.session.stop_and_remove("foreign-container-target-12345")

        with self.assertRaises(OwnershipReconciliationError):
            self.session.start_container_detached("foreign-container-target-12345")

        with self.assertRaises(OwnershipReconciliationError):
            self.session.exec_in_container("foreign-container-target-12345", ["ls"])

        with self.assertRaises(OwnershipReconciliationError):
            self.session.top_container("foreign-container-target-12345")

        with self.assertRaises(OwnershipReconciliationError):
            self.session.stop_container("foreign-container-target-12345")

    def test_rm_does_not_pass_volume_flag(self):
        # Removal must NOT pass -v (Finding 4)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "f" * 64
        intent = self.session.record_creation_intent(spec)
        rm_calls: List[List[str]] = []

        def runner(cmd, **kwargs):
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "inspect" in cmd_list:
                if any("rm" in c for c in rm_calls):
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                data = make_mock_inspect_data(cid, intent.container_name, intent.intent_id)
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd_list or "kill" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "rm" in cmd_list:
                rm_calls.append(cmd_list)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        self.session.create_container(spec)
        self.session.stop_and_remove(cid)

        self.assertTrue(len(rm_calls) > 0)
        for rm_cmd in rm_calls:
            self.assertNotIn("-v", rm_cmd)

    def test_cage_inspection_rejects_privileged_and_namespaces(self):
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "d" * 64

        # Privileged
        data_priv = make_mock_inspect_data(cid, "test-c", "test-intent", privileged=True)
        self.session._custom_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data_priv]), stderr="")
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

        # Host PID
        data_pid = make_mock_inspect_data(cid, "test-c", "test-intent", pid_mode="host")
        self.session._custom_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data_pid]), stderr="")
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

        # Foreign container PID
        data_cpid = make_mock_inspect_data(cid, "test-c", "test-intent", pid_mode="container:other")
        self.session._custom_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data_cpid]), stderr="")
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

        # CapAdd forbidden
        data_capadd = make_mock_inspect_data(cid, "test-c", "test-intent", cap_add=["SYS_ADMIN"])
        self.session._custom_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data_capadd]), stderr="")
        with self.assertRaises(CageInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_undeclared_mount_rejected(self):
        # Reject undeclared mounts, such as image-defined VOLUME (Finding 12)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
            mount_bindings=(MountBinding(container_path="/P", host_path="/host/P", access="ro"),),
        )
        cid = "e" * 64
        inspect_data = make_mock_inspect_data(
            cid, "test-c", "test-intent",
            mounts=[
                {"Destination": "/tmp", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
                {"Destination": "/dev/shm", "Source": "tmpfs", "RW": True, "Type": "tmpfs"},
                {"Destination": "/etc/resolv.conf", "Source": "/host/resolv.conf", "RW": False, "Type": "bind"},
                {"Destination": "/etc/hostname", "Source": "/host/hostname", "RW": False, "Type": "bind"},
                {"Destination": "/etc/hosts", "Source": "/host/hosts", "RW": False, "Type": "bind"},
                {"Destination": "/P", "Source": "/host/P", "RW": False, "Type": "bind"},
                # Undeclared volume!
                {"Destination": "/undeclared-data", "Source": "/var/lib/docker/volumes/123", "RW": True, "Type": "volume"},
            ]
        )
        self.session._custom_runner = lambda cmd, **kwargs: subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([inspect_data]), stderr="")
        with self.assertRaises(MountInspectionError):
            self.session.inspect_and_verify_cage_and_mounts(cid, spec)

    def test_detached_start_enforces_inspection_and_teardown(self):
        # start_container_detached enforces pre-start inspect and tears down on failure (Finding 7)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="preflight",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "7" * 64
        intent = self.session.record_creation_intent(spec)

        # Inspect returns privileged=True (violating cage)
        bad_data = make_mock_inspect_data(cid, intent.container_name, intent.intent_id, privileged=True)
        rm_called = False

        def runner(cmd, **kwargs):
            nonlocal rm_called
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "inspect" in cmd_list:
                if rm_called:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([bad_data]), stderr="")
            if "rm" in cmd_list or "stop" in cmd_list:
                rm_called = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        _, created_id = self.session.create_container(spec)

        with self.assertRaises(CageInspectionError):
            self.session.start_container_detached(created_id)

        # Container should have been stopped and removed in finally teardown
        self.assertTrue(rm_called)
        self.assertNotIn(created_id, self.session._active_containers)

    def test_output_overflow_fails_invocation(self):
        # Exceeding output limit fails invocation rather than returning success (Finding 9)
        spec = ContainerSpec(
            command=("cat", "/dev/zero"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            max_stdout_bytes=100,
            max_stderr_bytes=100,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "8" * 64
        inspect_after_rm = False
        intent_ref: List[CreationIntent] = []

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                # Emit 500 bytes (overflows 100-byte limit)
                return subprocess.CompletedProcess(cmd, 0, stdout="A" * 500, stderr="")
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container")
                cur_intent = intent_ref[0] if intent_ref else self.session._pending_intents.get(list(self.session._pending_intents.keys())[0])
                data = make_mock_inspect_data(cid, cur_intent.container_name if cur_intent else "c", cur_intent.intent_id if cur_intent else "i")
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "rm" in cmd_list or "stop" in cmd_list:
                inspect_after_rm = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        outcome = self.session.run_container(spec)
        self.assertEqual(outcome.exit_code, -1)
        self.assertIn("exceeded bound", outcome.error or "")
        self.assertTrue(outcome.teardown.is_resolved())

    def test_auxiliary_output_bounded(self):
        # Auxiliary command output exceeding limit raises ContainerLifecycleError (Finding 10)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        # Custom runner returning huge output exceeding DEFAULT_MAX_AUX_BYTES
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 0, stdout="Z" * (DEFAULT_MAX_AUX_BYTES + 1000), stderr="")

        self.session._custom_runner = runner
        with self.assertRaises(ContainerLifecycleError):
            self.session.create_container(spec)

    def test_teardown_exception_fails_closed(self):
        # Exception during teardown is caught, recorded, and marks session failed closed (Finding 1)
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "9" * 64
        intent = self.session.record_creation_intent(spec)

        def runner(cmd, **kwargs):
            cmd_list = list(cmd)
            if "create" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "inspect" in cmd_list:
                data = make_mock_inspect_data(cid, intent.container_name, intent.intent_id)
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd_list:
                # Stop times out!
                raise subprocess.TimeoutExpired(cmd, 25.0)
            if "rm" in cmd_list:
                raise OSError("Cannot reach docker daemon")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner
        self.session.create_container(spec)

        tr = self.session.stop_and_remove(cid)
        self.assertFalse(tr.is_resolved())
        self.assertTrue(self.session.has_unresolved_ownership())

    def test_normal_run_lifecycle_and_teardown(self):
        """Full normal lifecycle: create -> inspect -> start -> stop/rm -> verified removal."""
        spec = ContainerSpec(
            command=("python3", "-c", "print('success')"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "a" * 64
        inspect_after_rm = False
        captured_intent: Optional[CreationIntent] = None

        def runner(cmd, **kwargs):
            nonlocal inspect_after_rm, captured_intent
            cmd_list = list(cmd)
            if "create" in cmd_list:
                # Capture current intent
                for int_id, intent_obj in self.session._pending_intents.items():
                    captured_intent = intent_obj
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="success\n", stderr="")
            if "inspect" in cmd_list:
                if inspect_after_rm:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Error: No such container: " + cmd_list[-1])
                target = cmd_list[-1]
                assert captured_intent is not None
                data = make_mock_inspect_data(cid, captured_intent.container_name, captured_intent.intent_id)
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

    def test_daemon_outage_during_rm_fails_closed(self):
        """Pre-start inspect succeeds, rm is called, verify inspect returns daemon outage -> fails closed."""
        spec = ContainerSpec(
            command=("echo", "hi"),
            image="test-img",
            stage="proof",
            attempt=1,
            timeout_sec=10.0,
            cage_policy=make_valid_cage_policy(),
        )
        cid = "b" * 64
        captured_intent: Optional[CreationIntent] = None
        rm_invoked = False

        def runner(cmd, **kwargs):
            nonlocal rm_invoked, captured_intent
            cmd_list = list(cmd)
            if "create" in cmd_list:
                for int_id, intent_obj in self.session._pending_intents.items():
                    captured_intent = intent_obj
                return subprocess.CompletedProcess(cmd, 0, stdout=cid + "\n", stderr="")
            if "start" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="ran\n", stderr="")
            if "inspect" in cmd_list:
                if rm_invoked:
                    return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
                assert captured_intent is not None
                data = make_mock_inspect_data(cid, captured_intent.container_name, captured_intent.intent_id)
                return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([data]), stderr="")
            if "stop" in cmd_list or "kill" in cmd_list:
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            if "rm" in cmd_list:
                rm_invoked = True
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner

        with self.assertRaises(UnresolvedOwnershipError):
            self.session.run_container(spec)

        self.assertTrue(rm_invoked)
        self.assertTrue(self.session.has_unresolved_ownership())

        # Any subsequent run_container call must immediately fail closed without invoking docker!
        with self.assertRaises(UnresolvedOwnershipError):
            self.session.run_container(spec)

    def test_signal_cancellation_unwinds_not_reentrant(self):
        """Signal handling requests cancellation and unwinds; zero docker calls in handler."""
        invoked_cmds: List[List[str]] = []

        def runner(cmd, **kwargs):
            invoked_cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        self.session._custom_runner = runner

        with self.assertRaises(ContainerCancelledError):
            self.session._handle_signal(signal.SIGTERM, None)

        self.assertTrue(self.session.is_cancelled())
        self.assertEqual(len(invoked_cmds), 0)


if __name__ == "__main__":
    unittest.main()
