#!/usr/bin/env python3
"""Unit tests for check_action_pins."""

import json
import tempfile
import unittest
from pathlib import Path
from proof.check_action_pins import (
    PINNED_ACTIONS,
    check_action_pins,
    resolve_tag_sha,
)


class TestCheckActionPins(unittest.TestCase):
    def test_resolve_tag_sha_lightweight(self):
        output = "3d3c42e5aac5ba805825da76410c181273ba90b1\trefs/tags/v7.0.1\n"
        sha = resolve_tag_sha(output, "v7.0.1")
        self.assertEqual(sha, "3d3c42e5aac5ba805825da76410c181273ba90b1")

    def test_resolve_tag_sha_peeled(self):
        output = (
            "1111111111111111111111111111111111111111\trefs/tags/v7.0.1\n"
            "3d3c42e5aac5ba805825da76410c181273ba90b1\trefs/tags/v7.0.1^{}\n"
        )
        sha = resolve_tag_sha(output, "v7.0.1")
        self.assertEqual(sha, "3d3c42e5aac5ba805825da76410c181273ba90b1")

    def test_resolve_tag_sha_missing(self):
        output = "3d3c42e5aac5ba805825da76410c181273ba90b1\trefs/tags/v1.0.0\n"
        with self.assertRaises(ValueError):
            resolve_tag_sha(output, "v7.0.1")

    def test_check_action_pins_success(self):
        def mock_ls_remote(action, tag):
            expected = PINNED_ACTIONS[action]
            self.assertEqual(tag, expected["tag"])
            return f"{expected['sha']}\trefs/tags/{tag}\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "pins-report.json"
            report = check_action_pins(out_path=str(out_file), ls_remote_fn=mock_ls_remote)
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(len(report["actions"]), 6)
            for action, data in PINNED_ACTIONS.items():
                self.assertEqual(report["actions"][action]["sha"], data["sha"])
                self.assertEqual(report["actions"][action]["tag"], data["tag"])

            self.assertTrue(out_file.is_file())
            saved = json.loads(out_file.read_text())
            self.assertEqual(saved, report)

    def test_check_action_pins_mismatch(self):
        def mock_ls_remote(action, tag):
            if action == "actions/checkout":
                return "0000000000000000000000000000000000000000\trefs/tags/v7.0.1\n"
            expected = PINNED_ACTIONS[action]
            return f"{expected['sha']}\trefs/tags/{tag}\n"

        with self.assertRaises(RuntimeError) as ctx:
            check_action_pins(ls_remote_fn=mock_ls_remote)
        self.assertIn("Action pin verification failed", str(ctx.exception))

    def test_check_action_pins_network_error(self):
        def mock_ls_remote(action, tag):
            raise RuntimeError("Connection refused")

        with self.assertRaises(RuntimeError) as ctx:
            check_action_pins(ls_remote_fn=mock_ls_remote)
        self.assertIn("Action pin verification failed", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
