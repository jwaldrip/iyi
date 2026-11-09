#!/usr/bin/env python3
"""Pure fixture checks; never run a runner tool or the diagnostic."""
import copy
import json
import hashlib
import tempfile
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


    def test_measured_gcc_four_headers_and_unrecorded_paths(self):
        supplement = gate.load_gcc_baseline()
        entries = {item["requested"]: item for item in supplement["gcc_include_headers"]["files"]}
        with patch.object(gate, "check_path"), patch.object(gate, "verify_gcc_entry") as verify_entry:
            for name in ("stddef.h", "stdbool.h", "stdint.h", "stdarg.h"):
                path = str(gate.GCC_ROOT / name)
                item = gate.check_gcc_dependency(path, supplement)
                self.assertEqual(item, entries[path])
                self.assertEqual(len(item["sha256"]), 64)
                self.assertGreater(item["size"], 0)
            self.assertEqual(verify_entry.call_count, 4)
            for bad in (str(gate.GCC_ROOT / "unrecorded.h"),
                        str(gate.GCC_ROOT / "../include-unapproved/header.h"),
                        str(gate.GCC_ROOT) + "-unapproved/header.h"):
                with self.subTest(path=bad), self.assertRaises(ValueError):
                    gate.check_gcc_dependency(bad, supplement)

    def test_gcc_inventory_missing_and_added_files_fail(self):
        supplement = gate.load_gcc_baseline()
        entries = supplement["gcc_include_headers"]["files"]
        names = [str(Path(e["requested"]).relative_to(gate.GCC_ROOT)) for e in entries]
        root_stat = types.SimpleNamespace(st_uid=0, st_mode=0o40755)
        with patch.object(gate, "check_path"), patch.object(gate, "verify_gcc_entry"), \
             patch.object(Path, "stat", return_value=root_stat):
            with patch.object(gate.os, "walk", return_value=[(str(gate.GCC_ROOT), [], names)]):
                gate.verify_gcc_inventory(supplement)
            for changed in (names[:-1], names + ["extra.h"]):
                with self.subTest(count=len(changed)), \
                     patch.object(gate.os, "walk", return_value=[(str(gate.GCC_ROOT), [], changed)]):
                    with self.assertRaisesRegex(ValueError, "inventory changed"):
                        gate.verify_gcc_inventory(supplement)

    def test_gcc_supplement_incomplete_and_duplicate_rejected(self):
        supplement = gate.load_gcc_baseline()
        variants = []
        incomplete = copy.deepcopy(supplement)
        incomplete["gcc_include_headers"]["complete"] = False
        variants.append((incomplete, "inventory incomplete"))
        duplicate = copy.deepcopy(supplement)
        duplicate["gcc_include_headers"]["files"].append(
            copy.deepcopy(duplicate["gcc_include_headers"]["files"][0]))
        variants.append((duplicate, "duplicate GCC"))
        wrong_image = copy.deepcopy(supplement)
        wrong_image["image_version"] = "changed"
        variants.append((wrong_image, "image mismatch"))
        for value, message in variants:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as td:
                path = Path(td) / "fixture.json"
                payload = json.dumps(value).encode()
                path.write_bytes(payload)
                with patch.object(gate, "GCC_BASELINE", path), \
                     patch.object(gate, "GCC_CENSUS_SHA256", hashlib.sha256(payload).hexdigest()):
                    with self.assertRaisesRegex(ValueError, message):
                        gate.load_gcc_baseline()

    def test_gcc_symlink_target_change_fails(self):
        entry = {"path": "/fixture/link", "uid": 0, "gid": 0, "mode": "0o777",
                 "symlink_target": "expected"}
        st = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o120777)
        with patch.object(Path, "lstat", return_value=st), patch.object(gate.os, "readlink", return_value="changed"):
            with self.assertRaisesRegex(ValueError, "symlink mismatch"):
                gate.metadata(entry)

    def test_gcc_entry_escape_and_untrusted_ancestor_fail(self):
        supplement = gate.load_gcc_baseline()
        entry = copy.deepcopy(supplement["gcc_include_headers"]["files"][0])
        entry["canonical"] = "/outside/header"
        with self.assertRaisesRegex(ValueError, "escapes root"):
            gate.verify_gcc_entry(entry, gate.GCC_ROOT)
        entry = copy.deepcopy(supplement["gcc_include_headers"]["files"][0])
        unsafe = types.SimpleNamespace(st_uid=1000, st_mode=0o40755)
        with patch.object(Path, "stat", return_value=unsafe):
            with self.assertRaisesRegex(ValueError, "unsafe GCC ancestor"):
                gate.verify_gcc_entry(entry, gate.GCC_ROOT)

    def test_gcc_entry_same_size_mutation_and_missing_file_fail(self):
        supplement = gate.load_gcc_baseline()
        entry = copy.deepcopy(supplement["gcc_include_headers"]["files"][0])
        file_stat = types.SimpleNamespace(st_uid=entry["uid"], st_gid=entry["gid"],
                                          st_mode=0o100000 | int(entry["mode"], 8),
                                          st_size=entry["size"])
        dir_stat = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40755)
        def fixture_stat(path, *args, **kwargs):
            return file_stat if str(path) == entry["requested"] else dir_stat
        with patch.object(Path, "stat", autospec=True, side_effect=fixture_stat), \
             patch.object(Path, "resolve", return_value=Path(entry["canonical"])), \
             patch.object(gate, "metadata"), patch.object(gate, "digest", return_value="0" * 64):
            with self.assertRaisesRegex(ValueError, "file identity mismatch"):
                gate.verify_gcc_entry(entry, gate.GCC_ROOT)
        with patch.object(Path, "stat", side_effect=FileNotFoundError("fixture missing")):
            with self.assertRaises(FileNotFoundError):
                gate.verify_gcc_entry(entry, gate.GCC_ROOT)

    def test_changed_gcc_root_metadata_is_rejected(self):
        supplement = gate.load_gcc_baseline()
        root = supplement["gcc_include"]
        bad = types.SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40777)
        with patch.object(Path, "resolve", return_value=Path(root["canonical"])), \
             patch.object(Path, "lstat", return_value=bad):
            with self.assertRaisesRegex(ValueError, "metadata mismatch"):
                gate.verify_gcc_inventory(supplement)

    def test_real_symlink_escape_and_unrecorded_alias_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve() / "include"
            root.mkdir()
            outside = root.parent / "outside.h"
            outside.write_bytes(b"outside")
            target = root / "measured.h"
            target.write_bytes(b"target")
            escape = root / "escape.h"
            escape.symlink_to(outside)
            alias = root / "alias.h"
            alias.symlink_to(target)
            root_stat = root.stat()
            root_record = {"requested": str(root), "canonical": str(root), "regular": False,
                           "uid": root_stat.st_uid, "gid": root_stat.st_gid,
                           "mode": oct(root_stat.st_mode & 0o7777),
                           "chain": [], "canonical_ancestors": []}
            escape_record = {"requested": str(escape), "canonical": str(escape), "regular": True,
                             "size": len(b"outside"), "sha256": hashlib.sha256(b"outside").hexdigest(),
                             "uid": root_stat.st_uid, "gid": root_stat.st_gid, "mode": "0o644",
                             "chain": [], "canonical_ancestors": []}
            supplement = {"gcc_include": root_record, "gcc_include_headers": {"files": [escape_record]}}
            with patch.object(gate, "GCC_ROOT", root):
                with self.assertRaisesRegex(ValueError, "canonical path mismatch"):
                    gate.check_gcc_dependency(str(escape), supplement)
                with self.assertRaisesRegex(ValueError, "unrecorded GCC header"):
                    gate.check_gcc_dependency(str(alias), supplement)

if __name__ == "__main__":
    unittest.main()
