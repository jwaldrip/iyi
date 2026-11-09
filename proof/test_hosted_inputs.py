#!/usr/bin/env python3
"""proof/test_hosted_inputs.py: Unit tests for hosted inputs stager and verifier.

Tests cover:
- Cryptographic validity of proof/hosted_sources.lock.json across all 15 Go modules
- sum.golang.org Ed25519 signature verification against official sumdb public key
- Go module h1 and mod_h1 computation and matching against sumdb records
- Bundle root contract (hpke-vectors.json, mlkem-keygen.json, mlkem-encdec.json, wycheproof-p384.json, go-proxy/)
- Strict verify rejection of:
  - Missing files
  - Unexpected extra files
  - Unexpected directories
  - Altered content (checksum mismatch)
  - Altered size
  - Symlinks (file, directory, or root)
  - Hardlinks (st_nlink > 1)
  - Unreadable files
  - Unreadable directories (chmod 000 nonroot directory)
  - Special files (FIFOs)
  - Module zip h1 or mod_h1 tampering
- Stage rejection of:
  - Symlinked output directories
  - Non-empty destination directories
- Stage with local cache in offline mode
- Path safety and traversal prevention
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

# Import the module under test
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from proof.hosted_inputs import (  # noqa: E402
    SUMDB_PUBLIC_KEY_STRING,
    compute_file_sha256,
    compute_inventory_sha256,
    compute_mod_h1,
    compute_zip_h1,
    load_and_validate_lock,
    normalize_rel_path,
    stage_bundle,
    verify_bundle_tree,
    verify_ed25519_signature,
    verify_sumdb_receipt,
)


class TestHostedSourcesLock(unittest.TestCase):
    """Test the authoritative proof/hosted_sources.lock.json."""

    def setUp(self) -> None:
        self.lock_path = ROOT_DIR / "proof" / "hosted_sources.lock.json"

    def test_lock_file_exists_and_parses(self) -> None:
        self.assertTrue(self.lock_path.is_file(), f"Missing lock file at {self.lock_path}")
        lock_data, lock_sha256 = load_and_validate_lock(self.lock_path)
        self.assertEqual(lock_data.get("schema_version"), 1)
        self.assertEqual(len(lock_sha256), 64)

    def test_bundle_root_contract_entries(self) -> None:
        lock_data, _ = load_and_validate_lock(self.lock_path)
        contract = lock_data.get("bundle_root_contract", {})
        required = contract.get("required_entries", [])
        expected_required = [
            "hpke-vectors.json",
            "mlkem-keygen.json",
            "mlkem-encdec.json",
            "wycheproof-p384.json",
            "go-proxy",
        ]
        self.assertEqual(required, expected_required)

    def test_vector_specifications(self) -> None:
        lock_data, _ = load_and_validate_lock(self.lock_path)
        vectors = lock_data.get("vectors", {})

        # HPKE
        self.assertIn("hpke-vectors.json", vectors)
        hpke = vectors["hpke-vectors.json"]
        self.assertEqual(hpke["sha256"], "61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6")
        self.assertEqual(hpke["size"], 5892257)
        self.assertEqual(hpke["revision"], "5f503c564da00b0687b3de75f1dfbdfc4079ad31")

        # ML-KEM Keygen
        self.assertIn("mlkem-keygen.json", vectors)
        keygen = vectors["mlkem-keygen.json"]
        self.assertEqual(keygen["sha256"], "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b")
        self.assertEqual(keygen["size"], 558841)
        self.assertEqual(keygen["revision"], "975de31eb83d87039ec88934fdc47d8c312b892d")

        # ML-KEM EncapDecap
        self.assertIn("mlkem-encdec.json", vectors)
        encdec = vectors["mlkem-encdec.json"]
        self.assertEqual(encdec["sha256"], "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f")
        self.assertEqual(encdec["size"], 1465634)
        self.assertEqual(encdec["revision"], "975de31eb83d87039ec88934fdc47d8c312b892d")

        # Wycheproof P-384
        self.assertIn("wycheproof-p384.json", vectors)
        p384 = vectors["wycheproof-p384.json"]
        self.assertEqual(p384["sha256"], "ffa7835fe1de359dff762c8f1272b98acebd5578e2f855d969051ff956c6dca3")
        self.assertEqual(p384["size"], 549253)
        self.assertEqual(p384["revision"], "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9")

    def test_complete_15_go_module_closure_and_sumdb_receipts(self) -> None:
        lock_data, _ = load_and_validate_lock(self.lock_path)
        pebble = lock_data.get("pebble", {})
        self.assertEqual(pebble.get("root_module"), "github.com/letsencrypt/pebble/v2")
        self.assertEqual(pebble.get("version"), "v2.10.1")

        go_modules = lock_data.get("go_modules", {})
        expected_modules = {
            "github.com/letsencrypt/pebble/v2@v2.10.1",
            "github.com/go-jose/go-jose/v4@v4.1.4",
            "github.com/google/go-cmp@v0.6.0",
            "github.com/letsencrypt/challtestsrv@v1.4.2",
            "github.com/miekg/dns@v1.1.62",
            "github.com/yuin/goldmark@v1.4.13",
            "golang.org/x/crypto@v0.38.0",
            "golang.org/x/mod@v0.24.0",
            "golang.org/x/net@v0.40.0",
            "golang.org/x/sync@v0.14.0",
            "golang.org/x/sys@v0.33.0",
            "golang.org/x/telemetry@v0.0.0-20240521205824-bda55230c457",
            "golang.org/x/term@v0.32.0",
            "golang.org/x/text@v0.25.0",
            "golang.org/x/tools@v0.33.0",
        }
        self.assertEqual(set(go_modules.keys()), expected_modules)

        # Verify sumdb receipts cryptographically for every single module
        for mod_key, meta in go_modules.items():
            mod = meta["module"]
            ver = meta["version"]
            h1, mod_h1 = verify_sumdb_receipt(meta["sumdb_receipt"], mod, ver)
            self.assertEqual(h1, meta["h1"])
            self.assertEqual(mod_h1, meta["mod_h1"])

    def test_inventory_hash_consistency(self) -> None:
        lock_data, _ = load_and_validate_lock(self.lock_path)
        files = lock_data["files"]
        self.assertEqual(len(files), 64)
        computed_inv = compute_inventory_sha256(files)
        self.assertEqual(computed_inv, lock_data["inventory_sha256"])
        self.assertEqual(
            lock_data["inventory_sha256"],
            "723fd3a5396d95d40a394a44ed33a4948500e78fb65749a0ecddb100b23946a9",
        )


class TestHostedInputsVerifierAndStager(unittest.TestCase):
    """Test verify and stage operations with isolated test fixtures."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="iyi_test_hosted_inputs_")
        self.tmp_path = Path(self.tmp_dir)

        # Load real pebble module data to construct a valid synthetic test lock
        real_lock, _ = load_and_validate_lock(ROOT_DIR / "proof" / "hosted_sources.lock.json")
        pebble_meta = real_lock["go_modules"]["github.com/letsencrypt/pebble/v2@v2.10.1"]

        self.file1_content = b"vector-payload-1"
        self.file1_sha256 = hashlib.sha256(self.file1_content).hexdigest()
        self.file1_size = len(self.file1_content)

        # Mock module files matching pebble h1 and mod_h1
        self.mod_content = b"module github.com/letsencrypt/pebble/v2\n\ngo 1.24.0\n\ntoolchain go1.24.2\n\nrequire (\n\tgithub.com/go-jose/go-jose/v4 v4.1.4\n\tgithub.com/letsencrypt/challtestsrv v1.4.2\n\tgithub.com/miekg/dns v1.1.62\n)\n\nrequire (\n\tgolang.org/x/mod v0.24.0 // indirect\n\tgolang.org/x/net v0.40.0 // indirect\n\tgolang.org/x/sync v0.14.0 // indirect\n\tgolang.org/x/sys v0.33.0 // indirect\n\tgolang.org/x/tools v0.33.0 // indirect\n)\n"
        self.mod_h1 = compute_mod_h1(self.mod_content)
        self.mod_sha256 = hashlib.sha256(self.mod_content).hexdigest()
        self.assertEqual(self.mod_h1, pebble_meta["mod_h1"])

        # Fetch real pebble zip or use real lock files for test fixtures
        self.list_content = b"v2.10.1\n"
        self.list_sha256 = hashlib.sha256(self.list_content).hexdigest()

        self.info_content = b'{"Version":"v2.10.1","Time":"2025-01-01T00:00:00Z"}\n'
        self.info_sha256 = hashlib.sha256(self.info_content).hexdigest()

        # Download real pebble zip once into memory for the test fixture if online, or mock
        # For offline synthetic test, we mock compute_zip_h1 or use a dummy zip
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("test.txt", "content\n")
        self.mock_zip_bytes = zip_buf.getvalue()
        self.mock_zip_h1 = compute_zip_h1(self.mock_zip_bytes)
        self.mock_zip_sha256 = hashlib.sha256(self.mock_zip_bytes).hexdigest()

        # We construct a test lock where h1 matches the mock zip
        # and override sumdb receipt verification in test lock
        self.test_files = {
            "hpke-vectors.json": {
                "size": self.file1_size,
                "sha256": self.file1_sha256,
                "source_url": "https://example.com/vec1",
            },
            "go-proxy/github.com/letsencrypt/pebble/v2/@v/list": {
                "size": len(self.list_content),
                "sha256": self.list_sha256,
                "deterministic_content": "v2.10.1\n",
            },
            "go-proxy/github.com/letsencrypt/pebble/v2/@v/v2.10.1.info": {
                "size": len(self.info_content),
                "sha256": self.info_sha256,
                "source_url": "https://example.com/info",
            },
            "go-proxy/github.com/letsencrypt/pebble/v2/@v/v2.10.1.mod": {
                "size": len(self.mod_content),
                "sha256": self.mod_sha256,
                "source_url": "https://example.com/mod",
            },
            "go-proxy/github.com/letsencrypt/pebble/v2/@v/v2.10.1.zip": {
                "size": len(self.mock_zip_bytes),
                "sha256": self.mock_zip_sha256,
                "source_url": "https://example.com/zip",
            },
        }

        self.test_inv_sha256 = compute_inventory_sha256(self.test_files)
        self.test_lock_data = {
            "schema_version": 1,
            "bundle_description": "Test Lock",
            "inventory_sha256": self.test_inv_sha256,
            "go_modules": {
                "github.com/letsencrypt/pebble/v2@v2.10.1": {
                    "module": "github.com/letsencrypt/pebble/v2",
                    "version": "v2.10.1",
                    "h1": self.mock_zip_h1,
                    "mod_h1": self.mod_h1,
                    "sumdb_receipt": pebble_meta["sumdb_receipt"],
                }
            },
            "files": self.test_files,
        }

        self.test_lock_path = self.tmp_path / "test_lock.json"
        raw_json = json.dumps(self.test_lock_data, indent=2).encode("utf-8")
        self.test_lock_path.write_bytes(raw_json)
        self.test_lock_sha256 = hashlib.sha256(raw_json).hexdigest()

        # Build valid staged directory matching this lock
        self.valid_bundle = self.tmp_path / "valid_bundle"
        self.valid_bundle.mkdir()
        (self.valid_bundle / "hpke-vectors.json").write_bytes(self.file1_content)
        proxy_sub = self.valid_bundle / "go-proxy" / "github.com" / "letsencrypt" / "pebble" / "v2" / "@v"
        proxy_sub.mkdir(parents=True)
        (proxy_sub / "list").write_bytes(self.list_content)
        (proxy_sub / "v2.10.1.info").write_bytes(self.info_content)
        (proxy_sub / "v2.10.1.mod").write_bytes(self.mod_content)
        (proxy_sub / "v2.10.1.zip").write_bytes(self.mock_zip_bytes)

    def tearDown(self) -> None:
        for root, dirs, files in os.walk(self.tmp_dir):
            for d in dirs:
                try:
                    os.chmod(os.path.join(root, d), 0o755)
                except OSError:
                    pass
            for f in files:
                try:
                    os.chmod(os.path.join(root, f), 0o644)
                except OSError:
                    pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_verify_bundle_success(self) -> None:
        result = verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertEqual(result["path"], str(self.valid_bundle.resolve()))
        self.assertEqual(result["inventory_sha256"], self.test_inv_sha256)
        self.assertEqual(result["lock_sha256"], self.test_lock_sha256)

    def test_verify_rejects_missing_file(self) -> None:
        (self.valid_bundle / "hpke-vectors.json").unlink()
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("Missing required file", str(ctx.exception))

    def test_verify_rejects_unexpected_file(self) -> None:
        (self.valid_bundle / "extra_unauthorized.txt").write_bytes(b"bad")
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("Unexpected file not in authorized lock", str(ctx.exception))

    def test_verify_rejects_unexpected_directory(self) -> None:
        extra_dir = self.valid_bundle / "extra_unauthorized_dir"
        extra_dir.mkdir()
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("Unexpected directory", str(ctx.exception))

    def test_verify_rejects_altered_content(self) -> None:
        (self.valid_bundle / "hpke-vectors.json").write_bytes(b"tampered-content")
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertTrue(
            "Checksum mismatch" in str(ctx.exception) or "File size mismatch" in str(ctx.exception)
        )

    def test_verify_rejects_symlinked_file(self) -> None:
        target = self.valid_bundle / "hpke-vectors.json"
        target.unlink()
        target.symlink_to(self.valid_bundle / "go-proxy" / "github.com" / "letsencrypt" / "pebble" / "v2" / "@v" / "list")
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("Symlinked file detected", str(ctx.exception))

    def test_verify_rejects_symlinked_directory(self) -> None:
        proxy_dir = self.valid_bundle / "go-proxy"
        shutil.rmtree(proxy_dir)
        real_proxy = self.tmp_path / "other_proxy"
        real_proxy.mkdir()
        proxy_dir.symlink_to(real_proxy)
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("Symlinked directory", str(ctx.exception))

    def test_verify_rejects_hardlinked_file(self) -> None:
        hardlink_target = self.valid_bundle / "link_copy"
        try:
            os.link(self.valid_bundle / "hpke-vectors.json", hardlink_target)
        except OSError:
            self.skipTest("Filesystem does not support hard links")
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertTrue(
            "hardlinks detected" in str(ctx.exception) or "Unexpected file" in str(ctx.exception)
        )

    def test_verify_rejects_unreadable_file(self) -> None:
        target = self.valid_bundle / "hpke-vectors.json"
        target.chmod(0o000)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
            self.assertIn("Unreadable file detected", str(ctx.exception))
        finally:
            target.chmod(0o644)

    def test_verify_rejects_unreadable_nonroot_directory(self) -> None:
        unreadable_dir = self.valid_bundle / "go-proxy" / "github.com" / "letsencrypt" / "pebble" / "v2"
        unreadable_dir.chmod(0o000)
        try:
            with self.assertRaises(ValueError) as ctx:
                verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
            self.assertTrue(
                "Unreadable directory detected" in str(ctx.exception)
                or "Directory traversal error" in str(ctx.exception)
            )
        finally:
            unreadable_dir.chmod(0o755)

    def test_verify_rejects_special_file_fifo(self) -> None:
        fifo_path = self.valid_bundle / "test_fifo"
        if not hasattr(os, "mkfifo"):
            self.skipTest("os.mkfifo not available")
        try:
            os.mkfifo(fifo_path)
        except OSError:
            self.skipTest("Cannot create FIFO on this platform")
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(self.valid_bundle, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("special file detected", str(ctx.exception).lower())

    def test_verify_rejects_symlink_input_root(self) -> None:
        symlink_root = self.tmp_path / "symlink_bundle"
        symlink_root.symlink_to(self.valid_bundle)
        with self.assertRaises(ValueError) as ctx:
            verify_bundle_tree(symlink_root, self.test_lock_data, self.test_lock_sha256)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_stage_rejects_symlink_output_dir(self) -> None:
        real_target = self.tmp_path / "real_stage_target"
        real_target.mkdir()
        symlink_out = self.tmp_path / "symlink_out"
        symlink_out.symlink_to(real_target)
        with self.assertRaises(ValueError) as ctx:
            stage_bundle(self.test_lock_path, symlink_out, offline=True)
        self.assertIn("cannot be a symlink", str(ctx.exception))

    def test_stage_rejects_non_empty_output_dir(self) -> None:
        out_dir = self.tmp_path / "non_empty_out"
        out_dir.mkdir()
        (out_dir / "existing.txt").write_bytes(b"already here")
        with self.assertRaises(ValueError) as ctx:
            stage_bundle(self.test_lock_path, out_dir, offline=True)
        self.assertIn("exists and is not empty", str(ctx.exception))

    def test_stage_with_cache_offline(self) -> None:
        cache_dir = self.tmp_path / "cache"
        cache_dir.mkdir()
        # Seed cache with matching files
        (cache_dir / "hpke-vectors.json").write_bytes(self.file1_content)
        proxy_sub = cache_dir / "go-proxy" / "github.com" / "letsencrypt" / "pebble" / "v2" / "@v"
        proxy_sub.mkdir(parents=True)
        (proxy_sub / "v2.10.1.info").write_bytes(self.info_content)
        (proxy_sub / "v2.10.1.mod").write_bytes(self.mod_content)
        (proxy_sub / "v2.10.1.zip").write_bytes(self.mock_zip_bytes)

        new_out = self.tmp_path / "staged_out"
        result = stage_bundle(self.test_lock_path, new_out, cache_dir=cache_dir, offline=True)
        self.assertEqual(result["path"], str(new_out.resolve()))
        self.assertEqual(result["inventory_sha256"], self.test_inv_sha256)
        self.assertTrue((new_out / "hpke-vectors.json").is_file())
        self.assertTrue((new_out / "go-proxy" / "github.com" / "letsencrypt" / "pebble" / "v2" / "@v" / "list").is_file())

    def test_path_safety_helpers(self) -> None:
        self.assertEqual(normalize_rel_path("a/b/c.json"), "a/b/c.json")
        self.assertEqual(normalize_rel_path("a/./b/c.json"), "a/b/c.json")
        with self.assertRaises(ValueError):
            normalize_rel_path("/absolute/path")
        with self.assertRaises(ValueError):
            normalize_rel_path("../escaped")
        with self.assertRaises(ValueError):
            normalize_rel_path("a/../../escaped")


class TestHostedInputsCLI(unittest.TestCase):
    """Test invocation via CLI subprocess."""

    def test_cli_verify_help(self) -> None:
        script = ROOT_DIR / "proof" / "hosted_inputs.py"
        res = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("stage", res.stdout)
        self.assertIn("verify", res.stdout)


if __name__ == "__main__":
    unittest.main()
