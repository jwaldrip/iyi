import copy
import hashlib
import unittest

import host_custody_collect as collector
from host_custody_systemd import CustodyRefused, unit_name


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.manager = {"owner": ":1.25", "uid": 0, "pid": 1}
        self.subject, self.snapshot, self.policy = "a" * 64, "b" * 64, "c" * 64
        self.launch = {
            "subject_digest": self.subject, "snapshot_digest": self.snapshot,
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "manager_owner": ":1.25", "manager_uid": 0, "manager_pid": 1,
            "unit_name": unit_name(123, 2, self.subject),
            "unit_object": "/org/freedesktop/systemd1/unit/fixture_2eservice",
            "invocation_id": "1" * 32, "observer_uid": 61001,
            "observer_gid": 61001, "collector_uid": 501, "payload_uid": 1000,
            "effective_properties_digest": self.policy, "main_pid": 902,
            "exec_main_pid": 902, "cgroup": "/system.slice/fixture.service",
            "start_monotonic": 100, "control_descriptor": {
                "kind": "pipe", "direction": "collector-to-observer", "inherited": True},
        }
        self.output = {"stdout": b"PASS\n", "stderr": b""}
        self.export = b"exported evidence"
        def output(role, inode):
            data = self.output[role]
            return {"device": 1, "inode": inode, "uid": 501, "gid": 20,
                    "mode": 0o600, "nlink": 1, "size": len(data), "sha256": sha(data)}
        self.terminal = {k: self.launch[k] for k in (
            "subject_digest", "snapshot_digest", "boot_id", "manager_owner",
            "unit_name", "unit_object", "invocation_id", "exec_main_pid", "start_monotonic")}
        self.terminal.update({"exit_monotonic": 200, "exec_main_code": 1,
            "exec_main_status": 0, "result": "success", "n_restarts": 0,
            "outputs": {"stdout": output("stdout", 21), "stderr": output("stderr", 22)},
            "launch_digest": collector.canonical_digest(self.launch),
            "export": {"identity": "artifact:1", "size": len(self.export),
                       "sha256": sha(self.export), "readback_sha256": sha(self.export)}})

    def check_launch(self, launch=None, manager=None):
        collector.validate_launch(launch or self.launch, self.subject, self.snapshot,
                                  self.policy, manager or self.manager)

    def check_terminal(self, terminal=None, manager=None, output=None, export=None):
        return collector.validate_terminal(self.launch, terminal or self.terminal,
            manager or self.manager, output if output is not None else self.output,
            export if export is not None else self.export, 100, 100, 100)

    def test_consistency_is_not_authority(self):
        self.check_launch()
        self.assertEqual(self.check_terminal(), {"consistent_unattested": True, "strict_eligible": False})

    def test_wrong_manager_identity_and_owner_change(self):
        for manager in ({"owner": ":1.25", "uid": 0, "pid": 42},
                        {"owner": ":1.25", "uid": 501, "pid": 1},
                        {"owner": "org.freedesktop.systemd1", "uid": 0, "pid": 1}):
            with self.subTest(manager=manager), self.assertRaises(CustodyRefused):
                self.check_launch(manager=manager)
        with self.assertRaises(CustodyRefused):
            self.check_terminal(manager={"owner": ":1.26", "uid": 0, "pid": 1})

    def test_uid_collision_and_missing_barrier(self):
        for key, value in (("observer_uid", 501), ("observer_uid", 1000),
                           ("observer_uid", 0), ("main_pid", 903),
                           ("control_descriptor", {"kind": "file", "direction": "collector-to-observer", "inherited": True})):
            launch = copy.deepcopy(self.launch)
            launch[key] = value
            with self.subTest(key=key), self.assertRaises(CustodyRefused):
                self.check_launch(launch=launch)

    def test_stdout_pass_never_overrules_manager(self):
        for key, value in (("exec_main_status", 1), ("exec_main_code", 2),
                           ("result", "timeout"), ("result", "oom-kill"),
                           ("n_restarts", 1), ("exec_main_status", False)):
            record = copy.deepcopy(self.terminal)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(CustodyRefused):
                self.check_terminal(terminal=record)

    def test_pid_reuse_mismatched_invocation_missing_evidence(self):
        for key, value in (("invocation_id", "2" * 32), ("exec_main_pid", 903),
                           ("start_monotonic", 101), ("launch_digest", "d" * 64)):
            record = copy.deepcopy(self.terminal)
            record[key] = value
            with self.subTest(key=key), self.assertRaises(CustodyRefused):
                self.check_terminal(terminal=record)
        for key in ("exec_main_code", "exec_main_status", "exit_monotonic", "outputs", "export"):
            record = copy.deepcopy(self.terminal)
            del record[key]
            with self.subTest(key=key), self.assertRaises(CustodyRefused):
                self.check_terminal(terminal=record)

    def test_output_identity_contents_and_independent_readback(self):
        record = copy.deepcopy(self.terminal)
        record["outputs"]["stderr"]["inode"] = 21
        with self.assertRaises(CustodyRefused):
            self.check_terminal(terminal=record)
        with self.assertRaises(CustodyRefused):
            self.check_terminal(output={"stdout": b"forged PASS\n", "stderr": b""})
        with self.assertRaises(CustodyRefused):
            self.check_terminal(export=b"altered")
        with self.assertRaises(CustodyRefused):
            collector.validate_terminal(self.launch, self.terminal, self.manager, self.output, self.export, 0, 100, 100)


if __name__ == "__main__":
    unittest.main()
