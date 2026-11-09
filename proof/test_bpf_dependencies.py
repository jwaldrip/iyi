#!/usr/bin/env python3
"""
proof/test_bpf_dependencies.py: Focused unit and negative tests for authenticated BPF lock consumer.

Verifies:
1. Lock file structure, schema, and exact 4-package closure (rejection of missing/extra packages or missing artifacts).
2. URL validation and containment (scheme, hostname, query/credentials, path traversal).
3. Strict redirect rejection (preventing allowlist bypass).
4. GPG signature verification (approved fingerprint, rejection of untrusted keys and signature errors).
5. Release header parsing using pocket-relative entry namespace and index digest verification.
6. Bounded streaming reads and decompression (rejecting decompression bombs, incomplete streams, trailing data).
7. Deb archive preflight inspection (strict 3-member debian-binary 2.0 container, negative sizes, traversal paths, SUID/SGID, escaping links, device nodes, link-graph escapes).
8. Safe extraction containment, symlink ancestor rejection, RUNNER_TEMP containment, and unconditional non-root requirement.
9. Receipt destination containment, non-overlap with prefix/artifacts, and atomic exclusive creation.
"""

import io
import json
import lzma
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proof.bpf_dependencies import (
    APPROVED_KEY_ID,
    APPROVED_POCKETS,
    APPROVED_SIGNER_FINGERPRINT,
    DEFAULT_KEYRING_PATH,
    DEFAULT_KEYRING_SHA256,
    REQUIRED_PACKAGES,
    REQUIRED_STATIC_ARCHIVES,
    ArchiveCollisionInventory,
    SecurityError,
    StrictNoRedirectHandler,
    decompress_payload,
    decompress_xz_bounded,
    fetch_url,
    inspect_and_validate_deb_archive,
    parse_ar_members,
    parse_packages_index,
    parse_release_headers,
    run_lock_consumer,
    safe_extract_deb,
    sha256_bytes,
    sha256_file,
    validate_prefix_containment,
    validate_url,
    verify_gpg_signature,
)


class TestLockStructure(unittest.TestCase):
    def setUp(self):
        self.lock_path = REPO_ROOT / "proof" / "bpf_dependencies.lock.json"

    def test_production_lock_exists_and_valid(self):
        self.assertTrue(self.lock_path.is_file(), f"Missing {self.lock_path}")
        with open(self.lock_path, "r", encoding="utf-8") as f:
            lock = json.load(f)

        self.assertEqual(lock.get("schema_version"), "iyi-bpf-dependency-lock-v1")
        snapshot = lock.get("snapshot", {})
        self.assertEqual(snapshot.get("snapshot_id"), "20261105T000000Z")
        self.assertEqual(snapshot.get("distribution"), "ubuntu")
        self.assertEqual(snapshot.get("release"), "noble")
        self.assertEqual(snapshot.get("architecture"), "amd64")

        trust_root = lock.get("trust_root", {})
        self.assertIn(APPROVED_SIGNER_FINGERPRINT, trust_root.get("approved_signer_fingerprints", []))
        self.assertEqual(trust_root.get("approved_key_id"), APPROVED_KEY_ID)

        packages = lock.get("packages", {})
        self.assertEqual(set(packages.keys()), REQUIRED_PACKAGES)

        pockets = lock.get("metadata_pockets", {})
        self.assertEqual(set(pockets.keys()), APPROVED_POCKETS)
        for p_name, p_info in pockets.items():
            pkg_xz = p_info.get("packages_xz", {})
            self.assertEqual(pkg_xz.get("release_entry"), "main/binary-amd64/Packages.xz")
            self.assertEqual(pkg_xz.get("uncompressed_release_entry"), "main/binary-amd64/Packages")
            self.assertTrue(pkg_xz.get("url_path").startswith(f"dists/{p_name}/"))

        for pkg_name in REQUIRED_PACKAGES:
            pkg_info = packages[pkg_name]
            self.assertEqual(pkg_info["package"], pkg_name)
            self.assertTrue(pkg_info["version"])
            self.assertTrue(pkg_info["filename"].startswith("pool/main/"))
            self.assertGreater(pkg_info["size"], 0)
            self.assertEqual(len(pkg_info["sha256"]), 64)
            self.assertTrue(pkg_info["required_artifacts"])
            self.assertTrue(pkg_info["required_headers"])
            self.assertTrue(pkg_info["exclusion_rationale"])


class TestSecurityUrlValidation(unittest.TestCase):
    def test_valid_snapshot_url(self):
        url = "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z/dists/noble/InRelease"
        validate_url(url, "20261105T000000Z")

    def test_refuse_non_https(self):
        with self.assertRaises(SecurityError) as ctx:
            validate_url("http://snapshot.ubuntu.com/ubuntu/20261105T000000Z/InRelease", "20261105T000000Z")
        self.assertIn("Refusing non-HTTPS URL", str(ctx.exception))

    def test_refuse_untrusted_host(self):
        with self.assertRaises(SecurityError) as ctx:
            validate_url("https://evil.mirror.com/ubuntu/20261105T000000Z/InRelease", "20261105T000000Z")
        self.assertIn("Refusing untrusted host", str(ctx.exception))

    def test_refuse_credentials(self):
        with self.assertRaises(SecurityError) as ctx:
            validate_url("https://user:pass@snapshot.ubuntu.com/ubuntu/20261105T000000Z/InRelease", "20261105T000000Z")
        self.assertIn("Refusing URL credentials", str(ctx.exception))

    def test_refuse_query_or_fragment(self):
        with self.assertRaises(SecurityError) as ctx:
            validate_url("https://snapshot.ubuntu.com/ubuntu/20261105T000000Z/InRelease?foo=bar", "20261105T000000Z")
        self.assertIn("query or fragment", str(ctx.exception))

    def test_refuse_path_traversal(self):
        with self.assertRaises(SecurityError) as ctx:
            validate_url("https://snapshot.ubuntu.com/ubuntu/20261105T000000Z/dists/../../etc/passwd", "20261105T000000Z")
        self.assertIn("Path traversal detected in URL", str(ctx.exception))


class TestStrictRedirectRejection(unittest.TestCase):
    def test_redirect_handler_raises_security_error(self):
        handler = StrictNoRedirectHandler()
        with self.assertRaises(SecurityError) as ctx:
            handler.redirect_request(
                req=MagicMock(),
                fp=None,
                code=302,
                msg="Found",
                headers={},
                newurl="https://snapshot.ubuntu.com/redirected"
            )
        self.assertIn("HTTP redirect 302", str(ctx.exception))


class TestGpgVerification(unittest.TestCase):
    def setUp(self):
        self.temp_dir = os.path.realpath(tempfile.mkdtemp(prefix="iyi_test_gpg_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_keyring_missing(self):
        with self.assertRaises(SecurityError) as ctx:
            verify_gpg_signature(
                inrelease_bytes=b"dummy",
                keyring_path="/nonexistent/keyring.gpg",
                output_release_path=os.path.join(self.temp_dir, "rel"),
                gpgv_path="/usr/bin/gpgv",
                temp_dir=self.temp_dir
            )
        self.assertIn("Keyring not found", str(ctx.exception))

    def test_gpgv_failure_exit_code(self):
        keyring = os.path.join(self.temp_dir, "keyring.gpg")
        with open(keyring, "wb") as f:
            f.write(b"dummy keyring")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=2, stdout="", stderr="gpgv: bad signature")
            with self.assertRaises(SecurityError) as ctx:
                verify_gpg_signature(
                    inrelease_bytes=b"dummy",
                    keyring_path=keyring,
                    output_release_path=os.path.join(self.temp_dir, "rel"),
                    gpgv_path="/usr/bin/gpgv",
                    temp_dir=self.temp_dir
                )
            self.assertIn("gpgv failed with exit code 2", str(ctx.exception))

    def test_gpgv_unapproved_signer_fingerprint(self):
        keyring = os.path.join(self.temp_dir, "keyring.gpg")
        with open(keyring, "wb") as f:
            f.write(b"dummy keyring")

        fake_stdout = (
            "[GNUPG:] NEWSIG\n"
            "[GNUPG:] GOODSIG 12345678 Fake Key\n"
            "[GNUPG:] VALIDSIG AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-11-05 12345 0 4 0 1 10 01 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
            with self.assertRaises(SecurityError) as ctx:
                verify_gpg_signature(
                    inrelease_bytes=b"dummy",
                    keyring_path=keyring,
                    output_release_path=os.path.join(self.temp_dir, "rel"),
                    gpgv_path="/usr/bin/gpgv",
                    temp_dir=self.temp_dir
                )
            self.assertIn("Unapproved signer fingerprint", str(ctx.exception))

    def test_gpgv_signature_error_tag(self):
        keyring = os.path.join(self.temp_dir, "keyring.gpg")
        with open(keyring, "wb") as f:
            f.write(b"dummy keyring")

        fake_stdout = f"[GNUPG:] BADSIG {APPROVED_KEY_ID} Ubuntu Key\n"
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
            with self.assertRaises(SecurityError) as ctx:
                verify_gpg_signature(
                    inrelease_bytes=b"dummy",
                    keyring_path=keyring,
                    output_release_path=os.path.join(self.temp_dir, "rel"),
                    gpgv_path="/usr/bin/gpgv",
                    temp_dir=self.temp_dir
                )
            self.assertIn("signature failure: [GNUPG:] BADSIG", str(ctx.exception))


class TestReleaseAndPackagesParsing(unittest.TestCase):
    def test_parse_release_headers(self):
        release_text = (
            "Origin: Ubuntu\n"
            "Label: Ubuntu\n"
            "Suite: noble\n"
            "Version: 24.04\n"
            "Codename: noble\n"
            "Date: Thu, 25 Apr 2024 15:10:33 UTC\n"
            "Architectures: amd64 arm64\n"
            "Components: main restricted\n"
            "SHA256:\n"
            " 2a6a199e1031a5c279cb346646d594993f35b1c03dd4a82aaa0323980dd92451 1401160 main/binary-amd64/Packages.xz\n"
        )
        headers, sha256_files = parse_release_headers(release_text)
        self.assertEqual(headers.get("Origin"), "Ubuntu")
        self.assertEqual(headers.get("Codename"), "noble")
        self.assertIn("main/binary-amd64/Packages.xz", sha256_files)
        sha, sz = sha256_files["main/binary-amd64/Packages.xz"]
        self.assertEqual(sha, "2a6a199e1031a5c279cb346646d594993f35b1c03dd4a82aaa0323980dd92451")
        self.assertEqual(sz, 1401160)

    def test_parse_packages_index(self):
        packages_text = (
            "Package: libbpf-dev\n"
            "Version: 1:1.3.0-2build2\n"
            "Architecture: amd64\n"
            "Filename: pool/main/libb/libbpf/libbpf-dev_1.3.0-2build2_amd64.deb\n"
            "Size: 258996\n"
            "SHA256: c55e2dfed08e25f897798b37956d54ee687a7a13eb9b89b417a4ca9fbabc142f\n"
            "Depends: libbpf1 (= 1:1.3.0-2build2)\n"
            "\n"
            "Package: libelf-dev\n"
            "Version: 0.190-1.1ubuntu0.1\n"
            "Architecture: amd64\n"
            "Filename: pool/main/e/elfutils/libelf-dev_0.190-1.1ubuntu0.1_amd64.deb\n"
            "Size: 68530\n"
            "SHA256: 81affb95c29f7323f2ae24386aaa1f61d311578e3e27c5f78ef7b7d55cd3cf49\n"
            "\n"
        )
        pkgs = parse_packages_index(packages_text)
        self.assertIn("libbpf-dev", pkgs)
        self.assertIn("libelf-dev", pkgs)
        self.assertEqual(pkgs["libbpf-dev"]["Version"], "1:1.3.0-2build2")
        self.assertEqual(pkgs["libelf-dev"]["Size"], "68530")


class TestBoundedResourceAllocations(unittest.TestCase):
    def test_xz_decompression_bomb_rejection(self):
        raw = b"A" * 10000
        compressed = lzma.compress(raw)
        with self.assertRaises(SecurityError) as ctx:
            decompress_xz_bounded(compressed, expected_uncompressed_size=100)
        self.assertIn("exceeded bound", str(ctx.exception).lower())

    def test_xz_decompression_trailing_data_rejection(self):
        raw = b"valid xz data"
        compressed = lzma.compress(raw) + b"trailing garbage"
        with self.assertRaises(SecurityError) as ctx:
            decompress_xz_bounded(compressed, expected_uncompressed_size=len(raw))
        self.assertIn("trailing unconsumed data", str(ctx.exception).lower())

    def test_xz_decompression_incomplete_stream_rejection(self):
        raw = b"valid xz data"
        compressed = lzma.compress(raw)
        with self.assertRaises(SecurityError) as ctx:
            decompress_xz_bounded(compressed[:len(compressed)//2], expected_uncompressed_size=len(raw))
        self.assertIn("incomplete xz stream", str(ctx.exception).lower())

    def test_ar_parser_negative_size_rejection(self):
        bad_ar = (
            b"!<arch>\n"
            b"test_file       0           0     0     100644  -60       `\n"
        )
        with self.assertRaises(SecurityError) as ctx:
            parse_ar_members(bad_ar)
        self.assertIn("negative ar member size", str(ctx.exception).lower())

    def test_ar_parser_ambiguous_members_rejection(self):
        bad_ar = (
            b"!<arch>\n"
            b"debian-binary   0           0     0     100644  4         `\n2.0\n"
            b"control.tar.xz  0           0     0     100644  0         `\n"
            b"data.tar.xz     0           0     0     100644  0         `\n"
            b"extra.tar.xz    0           0     0     100644  0         `\n"
        )
        with self.assertRaises(SecurityError) as ctx:
            parse_ar_members(bad_ar)
        self.assertIn("exactly 3 members", str(ctx.exception).lower())

    def test_ar_parser_bad_debian_binary_version_rejection(self):
        bad_ar = (
            b"!<arch>\n"
            b"debian-binary   0           0     0     100644  4         `\n3.0\n"
            b"control.tar.xz  0           0     0     100644  0         `\n"
            b"data.tar.xz     0           0     0     100644  0         `\n"
        )
        with self.assertRaises(SecurityError) as ctx:
            parse_ar_members(bad_ar)
        self.assertIn("debian-binary member must be exactly", str(ctx.exception))


class TestDebPreflightAndArchiveValidation(unittest.TestCase):
    def _create_mock_deb(self, control_content: str, data_tar_members: list) -> bytes:
        deb_bin = b"2.0\n"

        ctrl_buf = io.BytesIO()
        with tarfile.open(fileobj=ctrl_buf, mode="w:xz") as tf:
            c_info = tarfile.TarInfo(name="control")
            c_bytes = control_content.encode("utf-8")
            c_info.size = len(c_bytes)
            c_info.mode = 0o644
            tf.addfile(c_info, io.BytesIO(c_bytes))
        ctrl_data = ctrl_buf.getvalue()

        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:xz") as tf:
            for item in data_tar_members:
                t_info = tarfile.TarInfo(name=item["name"])
                t_info.type = item.get("type", tarfile.REGTYPE)
                t_info.mode = item.get("mode", 0o644)
                if "linkname" in item:
                    t_info.linkname = item["linkname"]
                content = item.get("content", b"")
                t_info.size = len(content)
                if t_info.isreg():
                    tf.addfile(t_info, io.BytesIO(content))
                else:
                    tf.addfile(t_info)
        data_tar = data_buf.getvalue()

        out = bytearray(b"!<arch>\n")

        def add_ar_member(name, content):
            header = f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(content):<10}`\n"
            out.extend(header.encode("ascii"))
            out.extend(content)
            if len(content) % 2 == 1:
                out.extend(b"\n")

        add_ar_member("debian-binary", deb_bin)
        add_ar_member("control.tar.xz", ctrl_data)
        add_ar_member("data.tar.xz", data_tar)
        return bytes(out)

    def test_valid_deb_passes_preflight(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [
            {"name": "usr/include/bpf/bpf.h", "content": b"/* bpf.h */"},
            {"name": "usr/lib/x86_64-linux-gnu/libbpf.a", "content": b"!<arch>\n"}
        ]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)

    def test_missing_ar_magic_fails(self):
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(b"not an ar archive", "libbpf-dev", "1:1.3.0", "amd64", inv)
        self.assertIn("missing ar magic header", str(ctx.exception))

    def test_control_package_mismatch_fails(self):
        ctrl = "Package: evil-pkg\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        deb_bytes = self._create_mock_deb(ctrl, [])
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Package mismatch", str(ctx.exception))

    def test_control_version_mismatch_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 9:9.9.9\nArchitecture: amd64\n"
        deb_bytes = self._create_mock_deb(ctrl, [])
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Version mismatch", str(ctx.exception))

    def test_absolute_path_in_payload_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "/etc/shadow", "content": b"root::0:0:"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Absolute path in deb member", str(ctx.exception))

    def test_path_traversal_in_payload_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/include/../../../../etc/passwd", "content": b"root:x:0:0:"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Path traversal detected", str(ctx.exception))

    def test_setuid_mode_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/bin/evil", "mode": 0o4755, "content": b"evil"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Prohibited set-ID mode", str(ctx.exception))

    def test_setgid_mode_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/bin/evil", "mode": 0o2755, "content": b"evil"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Prohibited set-ID mode", str(ctx.exception))

    def test_device_node_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "dev/sda", "type": tarfile.BLKTYPE}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Prohibited file type", str(ctx.exception))

    def test_absolute_symlink_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/lib/libbpf.so", "type": tarfile.SYMTYPE, "linkname": "/lib/x86_64/libbpf.so"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Prohibited absolute symlink target", str(ctx.exception))

    def test_symlink_escaping_root_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/lib/libbpf.so", "type": tarfile.SYMTYPE, "linkname": "../../../../etc/passwd"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Symlink escapes root", str(ctx.exception))

    def test_symlink_graph_escape_fails(self):
        # Critical test: relative links a -> ., a/b -> ., b/c -> .. escaping prefix
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [
            {"name": "a", "type": tarfile.SYMTYPE, "linkname": "."},
            {"name": "a/b", "type": tarfile.SYMTYPE, "linkname": "."},
            {"name": "b/c", "type": tarfile.SYMTYPE, "linkname": ".."},
        ]
        deb_bytes = self._create_mock_deb(ctrl, members)
        inv = ArchiveCollisionInventory()
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64", inv)
        self.assertIn("Symlink escapes root", str(ctx.exception))


class TestExtractionContainment(unittest.TestCase):
    def test_root_user_refusal(self):
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(SecurityError) as ctx:
                run_lock_consumer(
                    lock_path="dummy.json",
                    output_prefix="/tmp/prefix",
                    receipt_path="/tmp/receipt.json",
                    check_only=True
                )
            self.assertIn("Refusing execution as root", str(ctx.exception))

    def test_system_directory_refusal(self):
        for sys_dir in ["/", "/usr", "/etc", "/var", "/bin", "/lib", "/tmp"]:
            with self.assertRaises(SecurityError) as ctx:
                validate_prefix_containment(sys_dir)
            self.assertIn("Refusing system directory", str(ctx.exception))

    def test_symlinked_ancestor_refusal(self):
        temp_dir = os.path.realpath(tempfile.mkdtemp(prefix="iyi_test_ancestor_"))
        try:
            real_parent = os.path.join(temp_dir, "real")
            os.makedirs(real_parent, mode=0o700)
            sym_parent = os.path.join(temp_dir, "symlink")
            os.symlink(real_parent, sym_parent)
            prefix = os.path.join(sym_parent, "target")
            with self.assertRaises(SecurityError) as ctx:
                validate_prefix_containment(prefix)
            self.assertIn("Ancestor directory is a symlink", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_receipt_overlapping_output_prefix_fails(self):
        temp_dir = os.path.realpath(tempfile.mkdtemp(prefix="iyi_test_receipt_"))
        try:
            prefix = os.path.join(temp_dir, "prefix")
            receipt = os.path.join(prefix, "receipt.json")
            with self.assertRaises(SecurityError) as ctx:
                run_lock_consumer(
                    lock_path="dummy.json",
                    output_prefix=prefix,
                    receipt_path=receipt
                )
            self.assertIn("Receipt destination path cannot be within output prefix", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


class TestSafeExtractDeb(unittest.TestCase):
    def setUp(self):
        self.temp_dir = os.path.realpath(tempfile.mkdtemp(prefix="iyi_test_extract_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_missing_dpkg_fails_without_fallback(self):
        deb_file = os.path.join(self.temp_dir, "test.deb")
        with open(deb_file, "wb") as f:
            f.write(b"dummy")
        with self.assertRaises(SecurityError) as ctx:
            safe_extract_deb(
                deb_path=deb_file,
                output_dir=self.temp_dir,
                dpkg_deb_path="/nonexistent/dpkg-deb"
            )
        self.assertIn("dpkg-deb executable not found", str(ctx.exception))


class TestExactContractEnforcement(unittest.TestCase):
    def setUp(self):
        self.temp_dir = os.path.realpath(tempfile.mkdtemp(prefix="iyi_test_contract_"))

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_extra_package_in_lock_rejected(self):
        mock_keyring = os.path.join(self.temp_dir, "mock_keyring.gpg")
        with open(mock_keyring, "wb") as f:
            f.write(b"mock keyring data")
        mock_keyring_sha = sha256_file(mock_keyring)

        bad_lock = {
            "schema_version": "iyi-bpf-dependency-lock-v1",
            "snapshot": {
                "snapshot_id": "20261105T000000Z",
                "base_url": "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z"
            },
            "trust_root": {
                "keyring_default_path": mock_keyring,
                "keyring_sha256": mock_keyring_sha
            },
            "packages": {
                "libbpf-dev": {},
                "libelf-dev": {},
                "libzstd-dev": {},
                "zlib1g-dev": {},
                "extra-unauthorized-pkg": {}
            }
        }
        lock_file = os.path.join(self.temp_dir, "bad_lock.json")
        with open(lock_file, "w", encoding="utf-8") as f:
            json.dump(bad_lock, f)

        with self.assertRaises(SecurityError) as ctx:
            run_lock_consumer(
                lock_path=lock_file,
                output_prefix=os.path.join(self.temp_dir, "prefix"),
                receipt_path=os.path.join(self.temp_dir, "receipt.json"),
                keyring_path=mock_keyring,
                check_only=True
            )
        self.assertIn("Lock packages must match exact required closure", str(ctx.exception))

    def test_unapproved_metadata_pocket_rejected_early(self):
        mock_keyring = os.path.join(self.temp_dir, "mock_keyring.gpg")
        with open(mock_keyring, "wb") as f:
            f.write(b"mock keyring data")
        mock_keyring_sha = sha256_file(mock_keyring)

        bad_lock = {
            "schema_version": "iyi-bpf-dependency-lock-v1",
            "snapshot": {
                "snapshot_id": "20261105T000000Z",
                "base_url": "https://snapshot.ubuntu.com/ubuntu/20261105T000000Z"
            },
            "trust_root": {
                "keyring_default_path": mock_keyring,
                "keyring_sha256": mock_keyring_sha
            },
            "packages": {
                "libbpf-dev": {"required_artifacts": [{"path": "usr/lib/x86_64-linux-gnu/libbpf.a"}], "required_headers": ["usr/include/bpf/bpf.h"]},
                "libelf-dev": {"required_artifacts": [{"path": "usr/lib/x86_64-linux-gnu/libelf.a"}], "required_headers": ["usr/include/libelf.h"]},
                "libzstd-dev": {"required_artifacts": [{"path": "usr/lib/x86_64-linux-gnu/libzstd.a"}], "required_headers": ["usr/include/zstd.h"]},
                "zlib1g-dev": {"required_artifacts": [{"path": "usr/lib/x86_64-linux-gnu/libz.a"}], "required_headers": ["usr/include/zlib.h"]}
            },
            "metadata_pockets": {
                "noble": {},
                "noble-updates": {},
                "noble-proposed": {}
            }
        }
        lock_file = os.path.join(self.temp_dir, "bad_pockets.json")
        with open(lock_file, "w", encoding="utf-8") as f:
            json.dump(bad_lock, f)

        with self.assertRaises(SecurityError) as ctx:
            run_lock_consumer(
                lock_path=lock_file,
                output_prefix=os.path.join(self.temp_dir, "prefix"),
                receipt_path=os.path.join(self.temp_dir, "receipt.json"),
                keyring_path=mock_keyring,
                check_only=True
            )
        self.assertIn("metadata_pockets keys must match exact approved set", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
