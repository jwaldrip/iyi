#!/usr/bin/env python3
"""
proof/test_bpf_dependencies.py: Focused unit and negative tests for authenticated BPF lock consumer.

Verifies:
1. Lock file structure and schema validation (missing fields, tampered values, bad URL).
2. URL validation and containment (scheme, hostname, query/credentials, path traversal).
3. GPG signature verification (approved fingerprint, rejection of untrusted keys and signature errors).
4. Release header and Packages.xz checksum verification.
5. Decompression safety and bounds (rejection of oversized/bomb payloads).
6. Packages index parsing and package record validation.
7. Deb archive preflight inspection (rejection of non-ar, traversal paths, SUID/SGID, escaping links, device nodes).
8. Safe extraction containment and non-root requirement.
9. Post-extraction artifact presence and digest verification.
"""

import io
import json
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
    APPROVED_SIGNER_FINGERPRINT,
    DEFAULT_KEYRING_PATH,
    DEFAULT_KEYRING_SHA256,
    REQUIRED_PACKAGES,
    SecurityError,
    decompress_payload,
    fetch_url,
    inspect_and_validate_deb_archive,
    parse_ar_members,
    parse_packages_index,
    parse_release_headers,
    run_lock_consumer,
    safe_extract_deb,
    sha256_bytes,
    sha256_file,
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

        for pkg_name in REQUIRED_PACKAGES:
            pkg_info = packages[pkg_name]
            self.assertEqual(pkg_info["package"], pkg_name)
            self.assertTrue(pkg_info["version"])
            self.assertTrue(pkg_info["filename"].startswith("pool/main/"))
            self.assertGreater(pkg_info["size"], 0)
            self.assertEqual(len(pkg_info["sha256"]), 64)
            self.assertTrue(pkg_info["required_artifacts"])
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
        self.assertIn("traversal", str(ctx.exception).lower())


class TestGpgVerification(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="iyi_test_gpg_")

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
            " 2a6a199e1031a5c279cb346646d594993f35b1c03dd4a82aaa0323980dd92451 1401160 dists/noble/main/binary-amd64/Packages.xz\n"
        )
        headers, sha256_files = parse_release_headers(release_text)
        self.assertEqual(headers.get("Origin"), "Ubuntu")
        self.assertEqual(headers.get("Codename"), "noble")
        self.assertIn("dists/noble/main/binary-amd64/Packages.xz", sha256_files)
        sha, sz = sha256_files["dists/noble/main/binary-amd64/Packages.xz"]
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
            header = f"{name:<16}{'0':<12}{'0':<6}{'0':<6}{'100644':<8}{len(content):<10}\x60\x0a"
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
        inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")

    def test_missing_ar_magic_fails(self):
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(b"not an ar archive", "libbpf-dev", "1:1.3.0", "amd64")
        self.assertIn("missing ar magic header", str(ctx.exception))

    def test_control_package_mismatch_fails(self):
        ctrl = "Package: evil-pkg\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        deb_bytes = self._create_mock_deb(ctrl, [])
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Package mismatch", str(ctx.exception))

    def test_control_version_mismatch_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 9:9.9.9\nArchitecture: amd64\n"
        deb_bytes = self._create_mock_deb(ctrl, [])
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Version mismatch", str(ctx.exception))

    def test_absolute_path_in_payload_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "/etc/shadow", "content": b"root::0:0:"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Absolute path in deb member", str(ctx.exception))

    def test_path_traversal_in_payload_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/include/../../../../etc/passwd", "content": b"root:x:0:0:"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Path traversal detected", str(ctx.exception))

    def test_setuid_mode_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/bin/evil", "mode": 0o4755, "content": b"evil"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Prohibited set-ID mode", str(ctx.exception))

    def test_setgid_mode_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/bin/evil", "mode": 0o2755, "content": b"evil"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Prohibited set-ID mode", str(ctx.exception))

    def test_device_node_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "dev/sda", "type": tarfile.BLKTYPE}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Prohibited file type", str(ctx.exception))

    def test_absolute_symlink_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/lib/libbpf.so", "type": tarfile.SYMTYPE, "linkname": "/lib/x86_64/libbpf.so"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Prohibited absolute symlink target", str(ctx.exception))

    def test_symlink_escaping_root_fails(self):
        ctrl = "Package: libbpf-dev\nVersion: 1:1.3.0-2build2\nArchitecture: amd64\n"
        members = [{"name": "usr/lib/libbpf.so", "type": tarfile.SYMTYPE, "linkname": "../../../../etc/passwd"}]
        deb_bytes = self._create_mock_deb(ctrl, members)
        with self.assertRaises(SecurityError) as ctx:
            inspect_and_validate_deb_archive(deb_bytes, "libbpf-dev", "1:1.3.0-2build2", "amd64")
        self.assertIn("Symlink escapes root", str(ctx.exception))


class TestExtractionContainment(unittest.TestCase):
    def test_root_user_refusal(self):
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(SecurityError) as ctx:
                run_lock_consumer(
                    lock_path="dummy.json",
                    output_prefix="/tmp/prefix",
                    receipt_path="/tmp/receipt.json"
                )
            self.assertIn("Refusing execution as root", str(ctx.exception))

    def test_system_directory_refusal(self):
        for sys_dir in ["/", "/usr", "/etc", "/var", "/bin", "/lib", "/tmp"]:
            with self.assertRaises(SecurityError) as ctx:
                run_lock_consumer(
                    lock_path="dummy.json",
                    output_prefix=sys_dir,
                    receipt_path="/tmp/receipt.json"
                )
            self.assertIn("Refusing system directory", str(ctx.exception))


class TestSafeExtractDeb(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="iyi_test_extract_")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_missing_dpkg_without_internal_flag_fails(self):
        deb_file = os.path.join(self.temp_dir, "test.deb")
        with open(deb_file, "wb") as f:
            f.write(b"dummy")
        with self.assertRaises(SecurityError) as ctx:
            safe_extract_deb(
                deb_path=deb_file,
                output_dir=self.temp_dir,
                dpkg_deb_path="/nonexistent/dpkg-deb",
                allow_internal_extractor=False
            )
        self.assertIn("dpkg-deb executable not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
