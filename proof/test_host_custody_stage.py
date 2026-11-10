import hashlib
import os
import tempfile
import unittest
from unittest import mock

import host_custody_stage as stage


class FakeExecutor:
    def __init__(self):
        self.files = {}
        self.modes = {}
        self.events = []
        self.limit = None
        self.bad_directory = False
        self.write_result = None
        self.inspect_fault = None
        self.mutate = None
        self.aborted = False

    def create_directory(self):
        return {"device": 1, "inode": 10, "uid": 1 if self.bad_directory else 0,
                "gid": 0, "mode": 0o700, "nlink": 2, "file_type": "directory"}

    def begin(self, role, basename, limit):
        assert basename == stage.ROLES[role]
        self.limit = limit
        self.files[role] = bytearray()
        self.modes[role] = 0o600
        self.events.append(("begin", role))

    def write(self, role, data):
        if self.mutate:
            action, self.mutate = self.mutate, None
            action()
        if self.write_result is not None:
            return self.write_result
        n = min(2, len(data))
        self.files[role].extend(data[:n])
        return n

    def finish(self, role):
        self.events.append(("finish", role))
        return 0

    def inspect(self, role):
        self.events.append(("inspect", role))
        data = self.files[role]
        result = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                  "device": 1, "inode": 20 + list(stage.ROLES).index(role),
                  "uid": 0, "gid": 0, "mode": self.modes[role], "nlink": 1,
                  "file_type": "regular"}
        if self.inspect_fault:
            result.update(self.inspect_fault)
        return result

    def expose(self, role, mode):
        self.events.append(("expose", role))
        self.modes[role] = mode

    def abort(self):
        self.aborted = True


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fd = os.open(self.tmp.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.artifacts = {}
        for role, name in stage.ROLES.items():
            data = (role + " contents").encode()
            with open(os.path.join(self.tmp.name, name), "wb") as f:
                f.write(data)
            self.artifacts[role] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                    "file_type": "regular", "mode": 0o555 if role == "observer" else 0o444}
        self.executor = FakeExecutor()

    def run_fixture(self):
        return stage._stage_fixture(self.fd, self.artifacts, self.executor, 10)

    def test_partial_writes_and_all_readbacks_before_exposure(self):
        result = self.run_fixture()
        self.assertEqual(set(result["artifacts"]), set(stage.ROLES))
        first = next(i for i, e in enumerate(self.executor.events) if e[0] == "expose")
        self.assertEqual(sum(e[0] == "inspect" for e in self.executor.events[:first]), len(stage.ROLES))
        self.assertEqual(self.executor.limit, self.artifacts["exec_config"]["size"] + 1)

    def test_authorization_is_not_bypassable(self):
        with mock.patch.object(stage.authorization, "authorize_runtime", side_effect=PermissionError("held")) as auth:
            with self.assertRaises(PermissionError):
                stage.stage({})
        auth.assert_called_once_with({})
        with mock.patch.object(stage.authorization, "authorize_runtime", return_value=None):
            with self.assertRaises(stage.StageRefused):
                stage.stage({})

    def test_leaf_symlink_and_fifo_refused(self):
        path = os.path.join(self.tmp.name, stage.ROLES["observer"])
        for kind in ("symlink", "fifo"):
            if os.path.lexists(path):
                os.unlink(path)
            if kind == "symlink":
                os.symlink(stage.ROLES["recipe"], path)
            else:
                os.mkfifo(path)
            with self.subTest(kind=kind), self.assertRaises((OSError, stage.StageRefused)):
                self.run_fixture()
            self.assertFalse(any(e[0] == "expose" for e in self.executor.events))

    def test_intermediate_symlink_refused(self):
        os.symlink(self.tmp.name, os.path.join(self.tmp.name, "link"))
        with self.assertRaises(OSError):
            stage._open_regular(self.fd, "link/observer")

    def test_short_and_long_source_refused(self):
        path = os.path.join(self.tmp.name, stage.ROLES["observer"])
        for data in (b"x", b"x" * 100):
            with open(path, "wb") as f:
                f.write(data)
            with self.subTest(length=len(data)), self.assertRaises(stage.StageRefused):
                self.run_fixture()
            self.assertFalse(any(e[0] == "expose" for e in self.executor.events))

    def test_changed_source_refused(self):
        path = os.path.join(self.tmp.name, stage.ROLES["observer"])
        def mutate():
            with open(path, "ab") as f:
                f.write(b"changed")
        self.executor.mutate = mutate
        with self.assertRaises(stage.StageRefused):
            self.run_fixture()
        self.assertTrue(self.executor.aborted)
        self.assertFalse(any(e[0] == "expose" for e in self.executor.events))

    def test_failed_and_zero_writes_refused(self):
        for result in (0, -1):
            self.executor.write_result = result
            with self.subTest(result=result), self.assertRaises(stage.StageRefused):
                self.run_fixture()
            self.assertFalse(any(e[0] == "expose" for e in self.executor.events))

    def test_invalid_directory_and_destination_refused(self):
        self.executor.bad_directory = True
        with self.assertRaises(stage.StageRefused):
            self.run_fixture()
        self.assertFalse(self.executor.events)
        self.executor.bad_directory = False
        self.executor.inspect_fault = {"nlink": 2}
        with self.assertRaises(stage.StageRefused):
            self.run_fixture()
        self.assertFalse(any(e[0] == "expose" for e in self.executor.events))

    def test_existing_destination_and_enospc_propagate(self):
        for error in (FileExistsError(), OSError(28, "No space left")):
            with self.subTest(error=error), mock.patch.object(self.executor, "begin", side_effect=error):
                with self.assertRaises(OSError):
                    self.run_fixture()
            self.assertTrue(self.executor.aborted)
            self.assertFalse(any(e[0] == "expose" for e in self.executor.events))


if __name__ == "__main__":
    unittest.main()
