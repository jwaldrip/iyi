#!/usr/bin/env python3
"""Pure fixture checks; never run a runner tool or the diagnostic."""
import copy
import json
from pathlib import Path
import subprocess
import types
import unittest
from unittest.mock import patch

import bpf_runner_baseline as gate


class BaselineFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw = gate.BASELINE.read_bytes()
        import hashlib
        assert hashlib.sha256(raw).hexdigest() == gate.CENSUS_SHA256
        cls.baseline = json.loads(raw)

    def test_exact_version_and_failures(self):
        expected = self.baseline["tools"]["clang18"]["version"]
        gate.compare_version(types.SimpleNamespace(returncode=0, stdout=expected["output"].encode()), expected)
        for result in (types.SimpleNamespace(returncode=1, stdout=expected["output"].encode()),
                       types.SimpleNamespace(returncode=0, stdout=b"different")):
            with self.assertRaises(ValueError):
                gate.compare_version(result, expected)

    def test_wrong_image_fails_before_inspection(self):
        with patch.object(gate, "check_path", side_effect=AssertionError("must not inspect")):
            with self.assertRaisesRegex(ValueError, "runner image"):
                gate.verify(self.baseline, {"ImageOS": "ubuntu24", "ImageVersion": "wrong"}, None)

    def test_changed_digest_rejected(self):
        entry = copy.deepcopy(self.baseline["tools"]["clang18"])
        st = types.SimpleNamespace(st_uid=entry["uid"], st_gid=entry["gid"],
                                   st_mode=int(entry["mode"], 8) | 0o100000, st_size=entry["size"])
        with patch.object(Path, "resolve", return_value=Path(entry["canonical"])), \
             patch.object(Path, "stat", return_value=st), \
             patch.object(gate, "metadata"), patch.object(gate, "digest", return_value="bad"):
            with self.assertRaisesRegex(ValueError, "file identity mismatch"):
                gate.check_path(entry, True)

    def test_injected_version_timeout_is_not_success(self):
        def timeout(_path):
            raise subprocess.TimeoutExpired("fixture", 5)
        import errno
        with patch.object(gate, "check_path"), \
             patch.object(gate.os, "getxattr", side_effect=OSError(errno.ENODATA, "no data"), create=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                gate.verify(self.baseline, {"ImageOS": "ubuntu24", "ImageVersion": "20261101.360.1"}, timeout)


if __name__ == "__main__":
    unittest.main()
