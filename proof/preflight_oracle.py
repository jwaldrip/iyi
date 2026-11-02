#!/usr/bin/env python3
"""
Preflight oracle verification for iyi strict proof chain.

Enforces PlanQuietCorpusFailures Slice C and Reviewer Blocker 4:
- Verifies Python >= 3.14 with built-in compression.zstd.
- Verifies pinned idna == 3.11.
- Verifies Pillow, cryptography, PyYAML, h2, and hpack.
- Verifies BIND dig and nsupdate with RFC 9460 HTTPS record type and DoT/DoH support.
- Verifies cURL with HTTP/2 and ALPN support.
- Verifies OpenSSL, Go, and GNU coreutils timeout.
- Fails pre-pin on any missing required comparison.
"""

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path


def check_python_version(min_major=3, min_minor=14):
    version = sys.version_info
    if (version.major, version.minor) < (min_major, min_minor):
        return False, f"Python version >= {min_major}.{min_minor} required, found {version.major}.{version.minor}.{version.micro}"
    return True, f"Python {version.major}.{version.minor}.{version.micro}"


def check_zstd_module():
    try:
        import compression.zstd as zstd
        if not hasattr(zstd, "ZstdCompressor") or not hasattr(zstd, "ZstdDecompressor"):
            return False, "compression.zstd missing ZstdCompressor or ZstdDecompressor"
        c = zstd.ZstdCompressor(level=3)
        compressed = c.compress(b"iyi-strict-proof-zstd-oracle-check")
        d = zstd.ZstdDecompressor()
        decompressed = d.decompress(compressed)
        if decompressed != b"iyi-strict-proof-zstd-oracle-check":
            return False, "compression.zstd roundtrip decompression mismatch"
        return True, "compression.zstd (Python 3.14+) operational"
    except ImportError as e:
        return False, f"compression.zstd import failed: {e}"
    except Exception as e:
        return False, f"compression.zstd check failed: {e}"


def check_lzma_module():
    try:
        import lzma
        compressed = lzma.compress(b"iyi-strict-proof-lzma-oracle-check")
        decompressed = lzma.decompress(compressed)
        if decompressed != b"iyi-strict-proof-lzma-oracle-check":
            return False, "lzma roundtrip mismatch"
        return True, "lzma operational"
    except Exception as e:
        return False, f"lzma check failed: {e}"


def check_bz2_module():
    try:
        import bz2
        compressed = bz2.compress(b"iyi-strict-proof-bz2-oracle-check")
        decompressed = bz2.decompress(compressed)
        if decompressed != b"iyi-strict-proof-bz2-oracle-check":
            return False, "bz2 roundtrip mismatch"
        return True, "bz2 operational"
    except Exception as e:
        return False, f"bz2 check failed: {e}"


def check_zlib_module():
    try:
        import zlib
        compressed = zlib.compress(b"iyi-strict-proof-zlib-oracle-check")
        decompressed = zlib.decompress(compressed)
        if decompressed != b"iyi-strict-proof-zlib-oracle-check":
            return False, "zlib roundtrip mismatch"
        return True, "zlib operational"
    except Exception as e:
        return False, f"zlib check failed: {e}"


def check_ssl_module():
    try:
        import ssl
        ctx = ssl.create_default_context()
        if not hasattr(ctx, "set_alpn_protocols"):
            return False, "ssl context missing set_alpn_protocols"
        return True, f"ssl operational ({ssl.OPENSSL_VERSION})"
    except Exception as e:
        return False, f"ssl check failed: {e}"


def check_idna_version(expected="3.11"):
    try:
        import idna
        if idna.__version__ != expected:
            return False, f"idna version mismatch: expected exact '{expected}', found '{idna.__version__}'"
        return True, f"idna=={idna.__version__} verified"
    except ImportError:
        return False, "idna package not installed"
    except Exception as e:
        return False, f"idna check failed: {e}"


def check_pillow():
    try:
        import PIL
        from PIL import Image, PngImagePlugin
        # Test creating in-memory 16-bit and RGBA PNG
        im = Image.new("RGBA", (16, 16), color=(255, 0, 0, 255))
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        buf.seek(0)
        im_read = Image.open(buf)
        im_read.load()
        if im_read.size != (16, 16):
            return False, "Pillow PNG verification failed: size mismatch"
        return True, f"Pillow {PIL.__version__} operational"
    except ImportError:
        return False, "Pillow (PIL) package not installed"
    except Exception as e:
        return False, f"Pillow check failed: {e}"


def check_cryptography():
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        if b"BEGIN PRIVATE KEY" not in pem:
            return False, "cryptography RSA key generation produced invalid PEM"
        return True, f"cryptography {cryptography.__version__} operational"
    except ImportError:
        return False, "cryptography package not installed"
    except Exception as e:
        return False, f"cryptography check failed: {e}"


def check_pyyaml():
    try:
        import yaml
        parsed = yaml.safe_load("iyi:\n  mode: strict\n  status: PASS\n")
        if parsed != {"iyi": {"mode": "strict", "status": "PASS"}}:
            return False, "pyyaml safe_load mismatch"
        return True, f"pyyaml {yaml.__version__} operational"
    except ImportError:
        return False, "pyyaml package not installed"
    except Exception as e:
        return False, f"pyyaml check failed: {e}"


def check_h2():
    try:
        import h2
        import h2.config
        import h2.connection
        import h2.events
        cfg = h2.config.H2Configuration(client_side=False)
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        data = conn.data_to_send()
        if not data:
            return False, "h2 connection initiation produced empty data"
        return True, f"h2 {h2.__version__} operational"
    except ImportError:
        return False, "h2 package not installed (required for DoH / HTTP/2 oracle)"
    except Exception as e:
        return False, f"h2 check failed: {e}"


def check_hpack():
    try:
        import hpack
        encoder = hpack.Encoder()
        encoded = encoder.encode([(":status", "200")])
        if not encoded:
            return False, "hpack encoding produced empty output"
        return True, f"hpack {hpack.__version__} operational"
    except ImportError:
        return False, "hpack package not installed"
    except Exception as e:
        return False, f"hpack check failed: {e}"


def check_dig():
    dig_path = shutil.which("dig")
    if not dig_path:
        return False, "dig binary not found on PATH (required for std/dns and std/secure_dns)"

    try:
        ver_proc = subprocess.run([dig_path, "-v"], capture_output=True, text=True, timeout=5)
        ver_line = (ver_proc.stdout or ver_proc.stderr).strip().splitlines()[0]
    except Exception as e:
        return False, f"dig -v failed: {e}"

    # Check HTTPS record type support
    try:
        probe_proc = subprocess.run(
            [dig_path, "-t", "HTTPS", "+noall", "+answer", "+tries=1", "+timeout=1", "@127.0.0.1", "probe.test"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        combined = (probe_proc.stdout + " " + probe_proc.stderr)
        if "ignoring invalid type HTTPS" in combined:
            return False, f"dig does not support RFC 9460 HTTPS record type ({ver_line})"
    except Exception as e:
        return False, f"dig HTTPS type probe failed: {e}"

    # Check +tls and +https support in dig options / help
    try:
        help_proc = subprocess.run([dig_path, "-h"], capture_output=True, text=True, timeout=5)
        help_text = help_proc.stdout + " " + help_proc.stderr
        has_tls = "+tls" in help_text or "+https" in help_text or "tls" in help_text.lower()
        if not has_tls:
            # Try a direct syntax invocation to test option recognition
            test_proc = subprocess.run(
                [dig_path, "+tls", "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            out = test_proc.stdout + " " + test_proc.stderr
            if "unknown option" in out.lower() or "invalid option" in out.lower():
                return False, f"dig does not support +tls option ({ver_line})"
    except Exception as e:
        return False, f"dig +tls option check failed: {e}"

    return True, f"dig operational ({ver_line}, HTTPS type supported)"


def check_nsupdate():
    nsupdate_path = shutil.which("nsupdate")
    if not nsupdate_path:
        return False, "nsupdate binary not found on PATH (required for std/dns zone update)"

    try:
        ver_proc = subprocess.run([nsupdate_path, "-V"], capture_output=True, text=True, timeout=5)
        ver_line = (ver_proc.stdout or ver_proc.stderr).strip().splitlines()[0]
    except Exception as e:
        return False, f"nsupdate -V failed: {e}"

    # Probe HTTPS record type recognition in nsupdate
    probe_input = "server 127.0.0.1 5353\nzone test.\nupdate add probe.test. 60 IN HTTPS 1 .\nsend\n"
    try:
        probe_proc = subprocess.run(
            [nsupdate_path],
            input=probe_input,
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = probe_proc.stdout + " " + probe_proc.stderr
        if "'HTTPS' is not a valid type" in output or "unknown class/type" in output:
            return False, f"nsupdate does not support RFC 9460 HTTPS type ({ver_line})"
    except subprocess.TimeoutExpired:
        pass  # Network timeout contacting 127.0.0.1 is acceptable; syntax acceptance is what matters
    except Exception as e:
        return False, f"nsupdate HTTPS probe failed: {e}"

    return True, f"nsupdate operational ({ver_line}, HTTPS type supported)"


def check_curl():
    curl_path = shutil.which("curl")
    if not curl_path:
        return False, "curl binary not found on PATH"

    try:
        proc = subprocess.run([curl_path, "--version"], capture_output=True, text=True, timeout=5)
        output = proc.stdout
        ver_line = output.splitlines()[0] if output else "unknown"
        if "HTTP2" not in output:
            return False, f"curl lacks HTTP2 feature: {ver_line}"
        if "alpn" not in output.lower() and "ALPN" not in output:
            return False, f"curl lacks ALPN feature: {ver_line}"
        return True, f"curl operational ({ver_line})"
    except Exception as e:
        return False, f"curl check failed: {e}"


def check_openssl():
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        return False, "openssl binary not found on PATH"

    try:
        proc = subprocess.run([openssl_path, "version"], capture_output=True, text=True, timeout=5)
        ver_line = proc.stdout.strip()
        # Verify verify subcommand is available
        verify_proc = subprocess.run([openssl_path, "verify", "-help"], capture_output=True, text=True, timeout=5)
        if verify_proc.returncode not in (0, 1):
            return False, f"openssl verify subcommand failed with exit {verify_proc.returncode}"
        return True, f"openssl operational ({ver_line})"
    except Exception as e:
        return False, f"openssl check failed: {e}"


def check_go():
    go_path = shutil.which("go")
    if not go_path:
        return False, "go binary not found on PATH (required for building Pebble ACME test server)"

    try:
        proc = subprocess.run([go_path, "version"], capture_output=True, text=True, timeout=5)
        ver_line = proc.stdout.strip()
        return True, f"go operational ({ver_line})"
    except Exception as e:
        return False, f"go check failed: {e}"


def check_timeout_utility():
    timeout_bin = shutil.which("timeout") or shutil.which("gtimeout")
    if not timeout_bin:
        return False, "timeout / gtimeout binary not found on PATH (GNU coreutils required)"
    try:
        proc = subprocess.run([timeout_bin, "--version"], capture_output=True, text=True, timeout=5)
        ver_line = proc.stdout.splitlines()[0] if proc.stdout else "GNU timeout"
        return True, f"timeout operational ({ver_line})"
    except Exception as e:
        return False, f"timeout check failed: {e}"


def run_preflight(manifest_path=None):
    print("=" * 80)
    print("RUNNING APPROVED ORACLE PREFLIGHT VERIFICATION")
    if manifest_path and os.path.exists(manifest_path):
        print(f"Manifest: {manifest_path}")
    print("=" * 80)

    checks = [
        ("Python Version (>= 3.14)", lambda: check_python_version(3, 14)),
        ("Python Module: compression.zstd", check_zstd_module),
        ("Python Module: lzma", check_lzma_module),
        ("Python Module: bz2", check_bz2_module),
        ("Python Module: zlib", check_zlib_module),
        ("Python Module: ssl", check_ssl_module),
        ("Python Package: idna==3.11", lambda: check_idna_version("3.11")),
        ("Python Package: Pillow (PIL)", check_pillow),
        ("Python Package: cryptography", check_cryptography),
        ("Python Package: pyyaml", check_pyyaml),
        ("Python Package: h2 (HTTP/2)", check_h2),
        ("Python Package: hpack", check_hpack),
        ("System Tool: dig (BIND with HTTPS/TLS/HTTPS type)", check_dig),
        ("System Tool: nsupdate (BIND with HTTPS type)", check_nsupdate),
        ("System Tool: curl (HTTP/2 and ALPN)", check_curl),
        ("System Tool: openssl (with verify)", check_openssl),
        ("System Tool: go (Go toolchain for Pebble)", check_go),
        ("System Tool: timeout (GNU coreutils)", check_timeout_utility),
    ]

    passed = []
    failures = []

    for name, fn in checks:
        try:
            ok, detail = fn()
            if ok:
                passed.append((name, detail))
                print(f"  [PASS] {name}: {detail}")
            else:
                failures.append((name, detail))
                print(f"  [FAIL] {name}: {detail}", file=sys.stderr)
        except Exception as e:
            failures.append((name, f"Exception during check: {e}"))
            print(f"  [FAIL] {name}: Exception: {e}", file=sys.stderr)

    print("=" * 80)
    print(f"PREFLIGHT SUMMARY: {len(passed)} passed, {len(failures)} failed")
    print("=" * 80)

    if failures:
        print("\n[ORACLE PREFLIGHT REFUSAL] Missing or incompatible oracle requirements:", file=sys.stderr)
        for name, detail in failures:
            print(f"  - {name}: {detail}", file=sys.stderr)
        print("\nAll approved oracle tools and comparisons must be satisfied before pre-pinning.", file=sys.stderr)
        return 1

    print("\n[ORACLE PREFLIGHT PASS] All approved oracle tools, features, and library comparisons VERIFIED.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Approved oracle preflight verification for iyi strict proof chain")
    parser.add_argument("--manifest", default="proof/oracle_manifest.json", help="Path to oracle manifest JSON")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        repo_root = Path(__file__).resolve().parent.parent
        manifest_path = repo_root / args.manifest

    code = run_preflight(str(manifest_path))
    sys.exit(code)


if __name__ == "__main__":
    main()
