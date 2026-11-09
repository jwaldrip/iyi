#!/usr/bin/env python3
"""
bpf_dependencies.py - Authenticated lock consumer for Ubuntu BPF build dependencies.

Implements the authenticated lock verification and safe nonroot extraction described in
PlanBpfOwnedDependencies (Sections 2 and 3).

Verifies the cryptographic chain:
  Ubuntu Archive Signing Key (2018) [F6ECB3762474EDA9D21B7022871920D1991BC93C]
    -> GPG-signed InRelease (noble, noble-updates, noble-security)
    -> SHA256 / size of Packages.xz index in Release checksums
    -> Package records in Packages index (Version, Filename, Size, SHA256, Source, Architecture, Depends)
    -> Exact .deb archive bytes (SHA256, Size)
    -> Deb archive internal control and payload preflight (no traversal, no setuid/setgid, no escaping links, link graph containment)
    -> Safe nonroot extraction via /usr/bin/dpkg-deb into private scratch prefix (mode 0700)
    -> Verification of exact 4 static archives ({libbpf.a, libelf.a, libz.a, libzstd.a}) and development headers
    -> Publication of verification receipt JSON recording authenticated provenance and digests.

Fails closed on any discrepancy, missing prerequisite, unapproved signer, or extraction safety violation.
"""

import argparse
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

APPROVED_SIGNER_FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
APPROVED_KEY_ID = "871920D1991BC93C"
DEFAULT_KEYRING_PATH = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
DEFAULT_KEYRING_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
REQUIRED_PACKAGES = {"libbpf-dev", "libelf-dev", "libzstd-dev", "zlib1g-dev"}
REQUIRED_STATIC_ARCHIVES = {
    "usr/lib/x86_64-linux-gnu/libbpf.a",
    "usr/lib/x86_64-linux-gnu/libelf.a",
    "usr/lib/x86_64-linux-gnu/libz.a",
    "usr/lib/x86_64-linux-gnu/libzstd.a",
}
ALLOWED_BASE_HOST = "snapshot.ubuntu.com"


class SecurityError(Exception):
    """Raised when any cryptographic, provenance, or containment check fails."""
    pass


class StrictNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject all HTTP redirects to prevent network allowlist bypass."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SecurityError(f"HTTP redirect {code} to {newurl} strictly prohibited")


def get_secure_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(StrictNoRedirectHandler())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def validate_url(url: str, snapshot_id: str) -> None:
    """Enforce strict URL allowlist and prevent traversal or credential smuggling."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise SecurityError(f"Refusing non-HTTPS URL: {url}")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        raise SecurityError(f"Refusing URL credentials: {url}")
    if parsed.hostname != ALLOWED_BASE_HOST or parsed.port is not None:
        raise SecurityError(f"Refusing untrusted host: {parsed.netloc} (expected {ALLOWED_BASE_HOST})")
    if parsed.query or parsed.fragment:
        raise SecurityError(f"Refusing URL with query or fragment: {url}")
    expected_prefix = f"/ubuntu/{snapshot_id}/"
    if not parsed.path.startswith(expected_prefix):
        raise SecurityError(f"URL path does not start with {expected_prefix}: {url}")
    if "/../" in parsed.path or parsed.path.endswith("/..") or "/./" in parsed.path or parsed.path.endswith("/."):
        raise SecurityError(f"Path traversal detected in URL: {url}")
    norm_path = os.path.normpath(parsed.path)
    if norm_path != parsed.path:
        raise SecurityError(f"Refusing non-normalized URL path: {parsed.path}")


def fetch_url(
    url: str,
    expected_size: int,
    snapshot_id: str,
    max_bytes: Optional[int] = None,
    cache_dir: Optional[str] = None
) -> bytes:
    """
    Fetch bytes via HTTPS with bounded streaming read and strict byte limit.
    Redirects are strictly rejected by StrictNoRedirectHandler.
    """
    validate_url(url, snapshot_id)
    limit = max_bytes or expected_size

    if cache_dir:
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", url)
        cached_path = os.path.join(cache_dir, safe_name)
        if os.path.isfile(cached_path):
            file_size = os.path.getsize(cached_path)
            if file_size != expected_size or file_size > limit:
                raise SecurityError(f"Cached file size mismatch for {url}: {file_size} != {expected_size}")
            buf = bytearray()
            with open(cached_path, "rb") as cf:
                while chunk := cf.read(65536):
                    buf.extend(chunk)
                    if len(buf) > limit:
                        raise SecurityError(f"Cached file exceeded byte limit ({len(buf)} > {limit})")
            return bytes(buf)

    opener = get_secure_opener()
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "iyi-bpf-dependencies/1.0 (+https://github.com/jwaldrip/iyi)"}
    )
    try:
        with opener.open(req, timeout=30) as resp:
            if resp.status != 200:
                raise SecurityError(f"HTTP status {resp.status} fetching {url}")
            cl = resp.headers.get("Content-Length")
            if cl and int(cl) != expected_size:
                raise SecurityError(f"Content-Length mismatch for {url}: header {cl} != expected {expected_size}")

            buf = bytearray()
            while chunk := resp.read(65536):
                buf.extend(chunk)
                if len(buf) > limit:
                    raise SecurityError(f"Streamed response exceeded limit ({len(buf)} > {limit}) for {url}")
            data = bytes(buf)
    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError(f"Failed fetching {url}: {e}") from e

    if len(data) != expected_size:
        raise SecurityError(f"Payload size mismatch for {url}: got {len(data)}, expected {expected_size}")

    if cache_dir:
        os.makedirs(cache_dir, mode=0o700, exist_ok=True)
        with open(cached_path, "wb") as cf:
            cf.write(data)

    return data


def decompress_xz_bounded(data: bytes, expected_uncompressed_size: int) -> bytes:
    """Decompress XZ data chunk by chunk enforcing bounded uncompressed size."""
    decompressor = lzma.LZMADecompressor()
    out = bytearray()
    chunk_size = 65536
    input_stream = io.BytesIO(data)
    while input_chunk := input_stream.read(chunk_size):
        decomp = decompressor.decompress(input_chunk, max_length=expected_uncompressed_size - len(out) + 1)
        out.extend(decomp)
        if len(out) > expected_uncompressed_size:
            raise SecurityError(
                f"Decompressed XZ output exceeded bound ({len(out)} > {expected_uncompressed_size})"
            )
    if not decompressor.eof:
        decomp = decompressor.decompress(b"", max_length=expected_uncompressed_size - len(out) + 1)
        out.extend(decomp)
        if len(out) > expected_uncompressed_size:
            raise SecurityError(
                f"Decompressed XZ output exceeded bound ({len(out)} > {expected_uncompressed_size})"
            )
    if len(out) != expected_uncompressed_size:
        raise SecurityError(
            f"Decompressed size mismatch: got {len(out)}, expected {expected_uncompressed_size}"
        )
    return bytes(out)


def decompress_payload(member_name: str, data: bytes, max_bytes: int = 200 * 1024 * 1024) -> bytes:
    """Decompress tar payload with strict byte ceiling to prevent decompression bombs."""
    if member_name.endswith(".zst"):
        try:
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(io.BytesIO(data))
            out = bytearray()
            while chunk := reader.read(65536):
                out.extend(chunk)
                if len(out) > max_bytes:
                    raise SecurityError(f"Decompressed zstd exceeded bound ({len(out)} > {max_bytes} bytes)")
            return bytes(out)
        except ImportError:
            p = subprocess.Popen(
                ["zstd", "-d", "-c", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            import threading
            def write_input():
                try:
                    p.stdin.write(data)
                    p.stdin.close()
                except Exception:
                    pass
            t = threading.Thread(target=write_input)
            t.start()
            out = bytearray()
            try:
                while chunk := p.stdout.read(65536):
                    out.extend(chunk)
                    if len(out) > max_bytes:
                        p.kill()
                        t.join(timeout=1)
                        raise SecurityError(f"Decompressed zstd exceeded bound ({len(out)} > {max_bytes} bytes)")
                t.join()
                p.wait()
                if p.returncode != 0:
                    err_msg = p.stderr.read().decode("utf-8", errors="replace")
                    raise SecurityError(f"zstd decompression failed (exit {p.returncode}): {err_msg}")
                return bytes(out)
            except Exception:
                p.kill()
                raise
    elif member_name.endswith(".xz"):
        decompressor = lzma.LZMADecompressor()
        out = bytearray()
        stream = io.BytesIO(data)
        while chunk := stream.read(65536):
            decomp = decompressor.decompress(chunk, max_length=max_bytes - len(out) + 1)
            out.extend(decomp)
            if len(out) > max_bytes:
                raise SecurityError(f"Decompressed xz exceeded bound ({len(out)} > {max_bytes} bytes)")
        return bytes(out)
    elif member_name.endswith(".gz"):
        import zlib
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = bytearray()
        stream = io.BytesIO(data)
        while chunk := stream.read(65536):
            decomp = d.decompress(chunk, max_bytes - len(out) + 1)
            out.extend(decomp)
            if len(out) > max_bytes:
                raise SecurityError(f"Decompressed gz exceeded bound ({len(out)} > {max_bytes} bytes)")
        decomp = d.flush()
        out.extend(decomp)
        if len(out) > max_bytes:
            raise SecurityError(f"Decompressed gz exceeded bound ({len(out)} > {max_bytes} bytes)")
        return bytes(out)
    else:
        if len(data) > max_bytes:
            raise SecurityError(f"Uncompressed payload exceeded bound ({len(data)} > {max_bytes} bytes)")
        return data


def parse_ar_members(deb_bytes: bytes, max_member_size: int = 50 * 1024 * 1024) -> List[Tuple[str, int, bytes]]:
    """Parse ar archive members from debian package bytes with strict size bounds."""
    if not deb_bytes.startswith(b"!<arch>\n"):
        raise SecurityError("Invalid .deb format: missing ar magic header !<arch>\n")
    pos = 8
    members = []
    while pos < len(deb_bytes):
        header = deb_bytes[pos:pos+60]
        if len(header) < 60:
            break
        name = header[:16].decode("ascii", errors="ignore").strip().rstrip("/")
        size_str = header[48:58].decode("ascii", errors="ignore").strip()
        try:
            size = int(size_str)
        except ValueError as e:
            raise SecurityError(f"Corrupt ar member size in deb: {size_str}") from e
        if size < 0:
            raise SecurityError(f"Negative ar member size in deb: {size}")
        if size > max_member_size:
            raise SecurityError(f"Ar member size exceeds limit: {size} > {max_member_size}")
        pos += 60
        member_data = deb_bytes[pos:pos+size]
        if len(member_data) != size:
            raise SecurityError(f"Truncated ar member: expected {size} bytes, got {len(member_data)}")
        pos += size
        if pos % 2 == 1:
            pos += 1
        members.append((name, size, member_data))
    return members


def verify_gpg_signature(
    inrelease_bytes: bytes,
    keyring_path: str,
    output_release_path: str,
    gpgv_path: str,
    temp_dir: str
) -> Tuple[str, str]:
    """
    Verify InRelease signature using gpgv with pinned keyring.
    Returns (fingerprint, keyid) on success, raises SecurityError on failure.
    """
    if not os.path.isfile(keyring_path):
        raise SecurityError(f"Keyring not found at {keyring_path}")

    inrelease_tmp = os.path.join(temp_dir, "current.InRelease")
    with open(inrelease_tmp, "wb") as f:
        f.write(inrelease_bytes)

    gnupg_home = os.path.join(temp_dir, "gnupg")
    os.makedirs(gnupg_home, mode=0o700, exist_ok=True)

    cmd = [
        gpgv_path,
        "--homedir", gnupg_home,
        "--keyring", keyring_path,
        "--status-fd", "1",
        "--output", output_release_path,
        inrelease_tmp,
    ]

    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SecurityError(f"gpgv failed with exit code {p.returncode}: stdout={p.stdout} stderr={p.stderr}")

    validsig_found = False
    valid_fingerprint = None
    valid_keyid = None

    for line in p.stdout.splitlines():
        if not line.startswith("[GNUPG:]"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        tag = parts[1]
        if tag in ("BADSIG", "ERRSIG", "REVKEYSIG", "EXPSIG", "NO_PUBKEY"):
            raise SecurityError(f"gpgv reported signature failure: {line}")
        if tag == "VALIDSIG" and len(parts) >= 3:
            valid_fingerprint = parts[2].upper()
            validsig_found = True
        if tag == "GOODSIG" and len(parts) >= 3:
            valid_keyid = parts[2].upper()

    if not validsig_found or not valid_fingerprint:
        raise SecurityError("gpgv succeeded but no VALIDSIG status tag was found in output")

    if valid_fingerprint != APPROVED_SIGNER_FINGERPRINT:
        raise SecurityError(
            f"Unapproved signer fingerprint: {valid_fingerprint} (expected {APPROVED_SIGNER_FINGERPRINT})"
        )

    return valid_fingerprint, (valid_keyid or APPROVED_KEY_ID)


def parse_release_headers(release_text: str) -> Tuple[Dict[str, str], Dict[str, Tuple[str, int]]]:
    """Parse verified Release body into headers dict and SHA256 files map."""
    headers: Dict[str, str] = {}
    sha256_files: Dict[str, Tuple[str, int]] = {}
    lines = release_text.splitlines()

    in_sha256 = False
    for line in lines:
        if line.startswith("SHA256:"):
            in_sha256 = True
            continue
        if in_sha256:
            if line.startswith(" ") or line.startswith("\t"):
                parts = line.strip().split()
                if len(parts) == 3:
                    sha256_files[parts[2]] = (parts[0], int(parts[1]))
            elif not line.startswith(" "):
                in_sha256 = False
        if not in_sha256 and ": " in line:
            k, v = line.split(": ", 1)
            headers[k] = v

    return headers, sha256_files


def parse_packages_index(raw_text: str) -> Dict[str, Dict[str, str]]:
    """Parse debian Packages stanzas into package_name -> fields mapping."""
    packages: Dict[str, Dict[str, str]] = {}
    blocks = raw_text.split("\n\n")
    for block in blocks:
        if not block.strip():
            continue
        fields: Dict[str, str] = {}
        current_key = None
        for line in block.splitlines():
            if line.startswith(" ") or line.startswith("\t"):
                if current_key:
                    fields[current_key] += " " + line.strip()
            elif ": " in line:
                k, v = line.split(": ", 1)
                fields[k] = v
                current_key = k
            elif ":" in line:
                k, v = line.split(":", 1)
                fields[k] = v.strip()
                current_key = k
        pkg = fields.get("Package")
        if pkg:
            packages[pkg] = fields
    return packages


def inspect_and_validate_deb_archive(
    deb_bytes: bytes,
    expected_pkg: str,
    expected_ver: str,
    expected_arch: str
) -> None:
    """
    Perform preflight safety scan on .deb before any extraction:
    - Compare control fields against package record.
    - Inspect every data.tar member: no path traversal, no setuid/setgid, no escaping links, no device nodes.
    - Track simulated directory and symlink graph to prevent link graph escapes.
    """
    members = parse_ar_members(deb_bytes)
    member_names = {m[0] for m in members}
    if "debian-binary" not in member_names:
        raise SecurityError("deb archive missing debian-binary member")

    # 1. Inspect control.tar
    control_member = next((m for m in members if m[0].startswith("control.tar")), None)
    if not control_member:
        raise SecurityError("deb archive missing control.tar member")
    control_tar_bytes = decompress_payload(control_member[0], control_member[2], max_bytes=10 * 1024 * 1024)

    tf_ctrl = tarfile.open(fileobj=io.BytesIO(control_tar_bytes))
    control_file = None
    for cm in tf_ctrl.getmembers():
        cm_name = cm.name
        if cm_name.startswith("./"):
            cm_name = cm_name[2:]
        if cm_name == "control":
            f = tf_ctrl.extractfile(cm)
            if f:
                control_file = f.read().decode("utf-8", errors="replace")
            break
    if not control_file:
        raise SecurityError("deb control.tar does not contain control file")

    ctrl_fields = {}
    for line in control_file.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            ctrl_fields[k] = v.strip()

    if ctrl_fields.get("Package") != expected_pkg:
        raise SecurityError(
            f"Control file Package mismatch: got {ctrl_fields.get('Package')}, expected {expected_pkg}"
        )
    if ctrl_fields.get("Version") != expected_ver:
        raise SecurityError(
            f"Control file Version mismatch: got {ctrl_fields.get('Version')}, expected {expected_ver}"
        )
    if ctrl_fields.get("Architecture") not in (expected_arch, "all"):
        raise SecurityError(
            f"Control file Architecture mismatch: got {ctrl_fields.get('Architecture')}, expected {expected_arch}"
        )

    # 2. Inspect data.tar with complete link graph simulation
    data_member = next((m for m in members if m[0].startswith("data.tar")), None)
    if not data_member:
        raise SecurityError("deb archive missing data.tar member")
    data_tar_bytes = decompress_payload(data_member[0], data_member[2], max_bytes=200 * 1024 * 1024)

    tf_data = tarfile.open(fileobj=io.BytesIO(data_tar_bytes))
    simulated_symlinks: Dict[str, str] = {}

    def resolve_path_in_graph(path_str: str, depth: int = 0) -> Optional[List[str]]:
        if depth > 40:
            raise SecurityError(f"Symlink loop or excessive nesting in path: {path_str}")
        if path_str.startswith("/"):
            return None
        cur_parts: List[str] = []
        for part in path_str.split("/"):
            if not part or part == ".":
                continue
            elif part == "..":
                if not cur_parts:
                    return None
                cur_parts.pop()
            else:
                cur_parts.append(part)
                cur_key = "/".join(cur_parts)
                if cur_key in simulated_symlinks:
                    target = simulated_symlinks[cur_key]
                    parent_parts = cur_parts[:-1]
                    target_full = "/".join(parent_parts + [target]) if parent_parts else target
                    resolved = resolve_path_in_graph(target_full, depth + 1)
                    if resolved is None:
                        return None
                    cur_parts = list(resolved)
        return cur_parts

    for m in tf_data.getmembers():
        raw_name = m.name
        if raw_name.startswith("/"):
            raise SecurityError(f"Absolute path in deb member: {raw_name}")
        if raw_name.startswith("./"):
            clean = raw_name[2:]
        elif raw_name == ".":
            continue
        else:
            clean = raw_name

        if not clean:
            continue

        if clean.startswith("/"):
            raise SecurityError(f"Absolute path in deb member: {clean}")

        norm = os.path.normpath(clean)
        if norm.startswith("..") or norm == ".." or "/../" in f"/{clean}/".replace("//", "/"):
            raise SecurityError(f"Path traversal detected in deb member: {clean}")

        # Check member type: reject device nodes, fifos, etc.
        if m.type not in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE):
            raise SecurityError(f"Prohibited file type {m.type} in deb member: {clean}")

        # Check setuid / setgid bits
        if m.mode & 0o6000 != 0:
            raise SecurityError(f"Prohibited set-ID mode ({oct(m.mode)}) in deb member: {clean}")

        # Resolve parent directory in simulated graph
        parent_dir = os.path.dirname(clean)
        if parent_dir:
            resolved_parent = resolve_path_in_graph(parent_dir)
            if resolved_parent is None:
                raise SecurityError(f"Path traverses through escaping directory/symlink: {clean}")
        else:
            resolved_parent = []

        # Check symlink target containment
        if m.issym():
            target = m.linkname
            if target.startswith("/"):
                raise SecurityError(f"Prohibited absolute symlink target in deb member {clean} -> {target}")
            target_full = "/".join(resolved_parent + [target]) if resolved_parent else target
            resolved_target = resolve_path_in_graph(target_full)
            if resolved_target is None:
                raise SecurityError(f"Symlink escapes root: {clean} -> {target}")
            simulated_symlinks[clean] = target

        # Check hardlink target containment
        if m.islnk():
            target = m.linkname
            if target.startswith("/"):
                raise SecurityError(f"Prohibited absolute hardlink target in deb member {clean} -> {target}")
            resolved_target = resolve_path_in_graph(target)
            if resolved_target is None:
                raise SecurityError(f"Hardlink escapes root: {clean} -> {target}")


def safe_extract_deb(deb_path: str, output_dir: str, dpkg_deb_path: str) -> None:
    """
    Extract .deb into output_dir nonroot using /usr/bin/dpkg-deb per PlanBpfOwnedDependencies.
    No fallback internal extractor is permitted.
    """
    resolved_dpkg = shutil.which(dpkg_deb_path) or dpkg_deb_path
    if not (os.path.isfile(resolved_dpkg) and os.access(resolved_dpkg, os.X_OK)):
        raise SecurityError(
            f"dpkg-deb executable not found at '{resolved_dpkg}'. Nonroot extraction requires dpkg-deb."
        )

    cmd = [resolved_dpkg, "--extract", deb_path, output_dir]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SecurityError(f"dpkg-deb --extract failed (exit {p.returncode}): {p.stderr}")


def validate_prefix_containment(output_prefix: str) -> str:
    """
    Enforce private job-directory containment per PlanBpfOwnedDependencies §3:
    - Verify non-root user.
    - Check all ancestors for symlinks.
    - Verify containment beneath RUNNER_TEMP if set.
    - Verify output directory is not an existing non-empty directory.
    - Set mode 0700.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SecurityError("Refusing execution as root. Dependency extraction must run as unprivileged user.")

    abs_output = os.path.abspath(output_prefix)
    system_dirs = {"/", "/usr", "/etc", "/var", "/home", "/bin", "/sbin", "/lib", "/lib64", "/tmp"}
    if abs_output in system_dirs:
        raise SecurityError(f"Refusing system directory as output prefix: {abs_output}")

    cur = os.path.dirname(abs_output)
    while cur and cur != "/":
        if os.path.islink(cur):
            if sys.platform == "darwin" and os.path.abspath(cur) in ("/var", "/etc", "/tmp"):
                pass
            else:
                raise SecurityError(f"Ancestor directory is a symlink: {cur}")
        cur = os.path.dirname(cur)

    runner_temp = os.environ.get("RUNNER_TEMP")
    if runner_temp:
        real_runner_temp = os.path.realpath(runner_temp)
        real_output = os.path.realpath(abs_output)
        if not real_output.startswith(real_runner_temp + "/") and real_output != real_runner_temp:
            raise SecurityError(f"Output prefix {abs_output} is not contained within RUNNER_TEMP ({runner_temp})")

    if os.path.exists(abs_output):
        if os.path.islink(abs_output):
            raise SecurityError(f"Output prefix is a symlink: {abs_output}")
        if os.listdir(abs_output):
            raise SecurityError(f"Output prefix directory already exists and is not empty: {abs_output}")
    else:
        old_umask = os.umask(0o077)
        try:
            os.makedirs(abs_output, mode=0o700, exist_ok=True)
        finally:
            os.umask(old_umask)

    os.chmod(abs_output, 0o700)
    st_out = os.stat(abs_output)
    if hasattr(os, "geteuid") and st_out.st_uid != os.geteuid():
        raise SecurityError(f"Output directory not owned by current user ({st_out.st_uid} != {os.geteuid()})")

    return abs_output


def run_lock_consumer(
    lock_path: str,
    output_prefix: str,
    receipt_path: str,
    keyring_path: Optional[str] = None,
    cache_dir: Optional[str] = None,
    gpgv_path: str = "/usr/bin/gpgv",
    dpkg_deb_path: str = "/usr/bin/dpkg-deb",
    check_only: bool = False
) -> Dict[str, Any]:
    """
    Main orchestrator implementing full cryptographic verification and safe extraction.
    Returns the receipt data structure on success; raises SecurityError on failure.
    """
    abs_output = validate_prefix_containment(output_prefix) if not check_only else os.path.abspath(output_prefix)

    # Validate receipt destination path (only when not check_only)
    abs_receipt = os.path.abspath(receipt_path)
    if not check_only:
        if os.path.islink(abs_receipt):
            raise SecurityError(f"Receipt destination path is a symlink: {abs_receipt}")
        cur = os.path.dirname(abs_receipt)
        while cur and cur != "/":
            if os.path.islink(cur):
                if sys.platform == "darwin" and os.path.abspath(cur) in ("/var", "/etc", "/tmp"):
                    pass
                else:
                    raise SecurityError(f"Receipt parent directory ancestor is a symlink: {cur}")
            cur = os.path.dirname(cur)

    # Stage 2: Load and validate lock schema
    if not os.path.isfile(lock_path):
        raise SecurityError(f"Lock file not found: {lock_path}")
    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)

    if lock.get("schema_version") != "iyi-bpf-dependency-lock-v1":
        raise SecurityError(f"Unsupported lock schema: {lock.get('schema_version')}")

    snapshot = lock.get("snapshot")
    if not snapshot or not isinstance(snapshot, dict):
        raise SecurityError("Lock missing snapshot definition")
    snapshot_id = snapshot.get("snapshot_id")
    base_url = snapshot.get("base_url")
    if not snapshot_id or not base_url:
        raise SecurityError("Lock snapshot missing snapshot_id or base_url")

    # Strict exact 4-package closure enforcement on lock definition in Stage 2
    packages_meta = lock.get("packages")
    if not packages_meta or not isinstance(packages_meta, dict):
        raise SecurityError("Lock missing packages definition")
    if set(packages_meta.keys()) != REQUIRED_PACKAGES:
        raise SecurityError(
            f"Lock packages must match exact required closure {REQUIRED_PACKAGES}, got {set(packages_meta.keys())}"
        )

    trust_root = lock.get("trust_root")
    if not trust_root or not isinstance(trust_root, dict):
        raise SecurityError("Lock missing trust_root definition")
    resolved_keyring = keyring_path or trust_root.get("keyring_default_path", DEFAULT_KEYRING_PATH)
    if not os.path.isfile(resolved_keyring):
        raise SecurityError(f"Ubuntu archive keyring not found at {resolved_keyring}")
    actual_keyring_sha = sha256_file(resolved_keyring)
    expected_keyring_sha = trust_root.get("keyring_sha256", DEFAULT_KEYRING_SHA256)
    if actual_keyring_sha != expected_keyring_sha:
        raise SecurityError(
            f"Keyring SHA256 mismatch for {resolved_keyring}: got {actual_keyring_sha}, expected {expected_keyring_sha}"
        )

    resolved_gpgv = shutil.which(gpgv_path) or gpgv_path
    if not (os.path.isfile(resolved_gpgv) and os.access(resolved_gpgv, os.X_OK)):
        raise SecurityError(f"gpgv binary not executable at {resolved_gpgv}")

    # Use RUNNER_TEMP for private scratch if available
    base_scratch_dir = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
    old_umask = os.umask(0o077)
    temp_scratch = tempfile.mkdtemp(prefix="iyi_bpf_lock_", dir=base_scratch_dir)
    os.umask(old_umask)

    try:
        # Stage 3: Authenticate Pockets (InRelease & Packages indices)
        pockets_meta = lock["metadata_pockets"]
        parsed_pockets: Dict[str, Dict[str, Dict[str, str]]] = {}
        verified_pockets_summary: List[Dict[str, Any]] = []
        freshness = lock.get("freshness_policy", {})

        for pocket_name, pocket_info in pockets_meta.items():
            inrelease_rel_path = pocket_info["inrelease_path"]
            inrelease_url = f"{base_url}/{inrelease_rel_path}"
            validate_url(inrelease_url, snapshot_id)

            expected_size = pocket_info["inrelease_size"]
            expected_sha = pocket_info["inrelease_sha256"]

            inrelease_bytes = fetch_url(
                inrelease_url,
                expected_size=expected_size,
                snapshot_id=snapshot_id,
                cache_dir=cache_dir
            )
            actual_inrelease_sha = sha256_bytes(inrelease_bytes)
            if actual_inrelease_sha != expected_sha:
                raise SecurityError(
                    f"InRelease SHA256 mismatch for {pocket_name}: got {actual_inrelease_sha}, expected {expected_sha}"
                )

            # GPG verification with gpgv
            output_release = os.path.join(temp_scratch, f"{pocket_name}.release")
            signer_fp, signer_keyid = verify_gpg_signature(
                inrelease_bytes=inrelease_bytes,
                keyring_path=resolved_keyring,
                output_release_path=output_release,
                gpgv_path=resolved_gpgv,
                temp_dir=temp_scratch
            )

            with open(output_release, "r", encoding="utf-8", errors="replace") as rf:
                release_text = rf.read()
            headers, sha256_files = parse_release_headers(release_text)

            # Header assertions
            if headers.get("Origin") != "Ubuntu" or headers.get("Label") != "Ubuntu":
                raise SecurityError(f"Invalid release origin/label in {pocket_name}: {headers.get('Origin')}/{headers.get('Label')}")
            if headers.get("Suite") != pocket_name:
                raise SecurityError(f"Suite mismatch in {pocket_name}: got {headers.get('Suite')}")
            if headers.get("Codename") != "noble" or headers.get("Version") != "24.04":
                raise SecurityError(f"Release codename/version mismatch in {pocket_name}: {headers.get('Codename')} {headers.get('Version')}")
            if "amd64" not in headers.get("Architectures", ""):
                raise SecurityError(f"amd64 architecture missing from {pocket_name}")
            if "main" not in headers.get("Components", ""):
                raise SecurityError(f"main component missing from {pocket_name}")

            # Freshness verification
            release_date = headers.get("Date")
            if not release_date:
                raise SecurityError(f"Missing Date header in {pocket_name} InRelease")
            if pocket_name == freshness.get("frozen_base_pocket", "noble"):
                if not freshness.get("frozen_base_pocket_allow_historical", False):
                    raise SecurityError(f"Historical date not allowed for base pocket {pocket_name}")
                expected_base_date = freshness.get("frozen_base_pocket_date")
                if expected_base_date and release_date != expected_base_date:
                    raise SecurityError(f"Base pocket date mismatch: got {release_date}, expected {expected_base_date}")
            else:
                if release_date != pocket_info.get("date"):
                    raise SecurityError(
                        f"Date mismatch for {pocket_name}: got {release_date}, expected {pocket_info.get('date')}"
                    )

            # Check Packages.xz entry in verified release
            pkg_xz_info = pocket_info["packages_xz"]
            release_entry = pkg_xz_info.get("release_entry", "main/binary-amd64/Packages.xz")
            if release_entry not in sha256_files:
                raise SecurityError(f"Index {release_entry} not found in verified {pocket_name} Release checksums")
            rel_sha, rel_size = sha256_files[release_entry]
            if rel_sha != pkg_xz_info["sha256"] or rel_size != pkg_xz_info["size"]:
                raise SecurityError(
                    f"Index {release_entry} checksum in Release mismatch with lock ({rel_sha} vs {pkg_xz_info['sha256']})"
                )

            # Fetch Packages.xz using url_path
            url_path = pkg_xz_info.get("url_path", f"dists/{pocket_name}/{release_entry}")
            index_url = f"{base_url}/{url_path}"
            validate_url(index_url, snapshot_id)
            index_bytes = fetch_url(
                index_url,
                expected_size=pkg_xz_info["size"],
                snapshot_id=snapshot_id,
                cache_dir=cache_dir
            )
            actual_index_sha = sha256_bytes(index_bytes)
            if actual_index_sha != pkg_xz_info["sha256"]:
                raise SecurityError(f"Downloaded Packages.xz SHA256 mismatch for {pocket_name}")

            # Bounded decompress
            uncompressed_bytes = decompress_xz_bounded(index_bytes, pkg_xz_info["uncompressed_size"])
            actual_uncomp_sha = sha256_bytes(uncompressed_bytes)
            if actual_uncomp_sha != pkg_xz_info["uncompressed_sha256"]:
                raise SecurityError(f"Uncompressed Packages SHA256 mismatch for {pocket_name}")

            parsed_stanzas = parse_packages_index(uncompressed_bytes.decode("utf-8", errors="replace"))
            parsed_pockets[pocket_name] = parsed_stanzas

            verified_pockets_summary.append({
                "pocket": pocket_name,
                "inrelease_sha256": actual_inrelease_sha,
                "date": release_date,
                "signer_fingerprint": signer_fp,
                "packages_index_sha256": actual_index_sha
            })

        # Stage 4: Strict Exact 4-Package Contract Validation
        packages_meta = lock["packages"]
        if set(packages_meta.keys()) != REQUIRED_PACKAGES:
            raise SecurityError(
                f"Lock packages must match exact required closure {REQUIRED_PACKAGES}, got {set(packages_meta.keys())}"
            )

        verified_packages_summary: Dict[str, Any] = {}
        staged_deb_files: List[Tuple[str, str, Dict[str, Any]]] = []

        for pkg_name in sorted(REQUIRED_PACKAGES):
            pkg_info = packages_meta[pkg_name]
            pocket_name = pkg_info["pocket"]
            if pocket_name not in parsed_pockets:
                raise SecurityError(f"Package {pkg_name} refers to unknown pocket {pocket_name}")

            pocket_stanzas = parsed_pockets[pocket_name]
            if pkg_name not in pocket_stanzas:
                raise SecurityError(f"Package {pkg_name} not found in pocket {pocket_name} Packages index")

            rec = pocket_stanzas[pkg_name]
            if rec.get("Version") != pkg_info["version"]:
                raise SecurityError(f"Version mismatch for {pkg_name}: got {rec.get('Version')}, expected {pkg_info['version']}")
            if rec.get("Filename") != pkg_info["filename"]:
                raise SecurityError(f"Filename mismatch for {pkg_name}: got {rec.get('Filename')}, expected {pkg_info['filename']}")
            if rec.get("SHA256") != pkg_info["sha256"]:
                raise SecurityError(f"SHA256 mismatch for {pkg_name}: got {rec.get('SHA256')}, expected {pkg_info['sha256']}")
            if int(rec.get("Size", "0")) != pkg_info["size"]:
                raise SecurityError(f"Size mismatch for {pkg_name}: got {rec.get('Size')}, expected {pkg_info['size']}")
            if rec.get("Architecture") != pkg_info["architecture"]:
                raise SecurityError(f"Architecture mismatch for {pkg_name}: got {rec.get('Architecture')}, expected {pkg_info['architecture']}")
            if rec.get("Source", pkg_name).split()[0] != pkg_info["source"].split()[0]:
                raise SecurityError(f"Source mismatch for {pkg_name}: got {rec.get('Source')}, expected {pkg_info['source']}")
            if rec.get("Depends") != pkg_info["depends"]:
                raise SecurityError(f"Depends mismatch for {pkg_name}: got {rec.get('Depends')}, expected {pkg_info['depends']}")

            # Contract verification: required artifacts and headers must be specified
            req_artifacts = pkg_info.get("required_artifacts")
            if not req_artifacts or not isinstance(req_artifacts, list):
                raise SecurityError(f"Package {pkg_name} must declare non-empty required_artifacts")
            req_headers = pkg_info.get("required_headers")
            if not req_headers or not isinstance(req_headers, list):
                raise SecurityError(f"Package {pkg_name} must declare non-empty required_headers")

            # Stage 5: Fetch .deb archive and perform preflight inspection
            deb_url = f"{base_url}/{pkg_info['filename']}"
            validate_url(deb_url, snapshot_id)
            deb_bytes = fetch_url(
                deb_url,
                expected_size=pkg_info["size"],
                snapshot_id=snapshot_id,
                cache_dir=cache_dir
            )
            actual_deb_sha = sha256_bytes(deb_bytes)
            if actual_deb_sha != pkg_info["sha256"]:
                raise SecurityError(f"Downloaded deb SHA256 mismatch for {pkg_name}")

            inspect_and_validate_deb_archive(
                deb_bytes=deb_bytes,
                expected_pkg=pkg_name,
                expected_ver=pkg_info["version"],
                expected_arch=pkg_info["architecture"]
            )

            # Save deb to temporary scratch for dpkg-deb extraction
            deb_scratch_path = os.path.join(temp_scratch, os.path.basename(pkg_info["filename"]))
            with open(deb_scratch_path, "wb") as df:
                df.write(deb_bytes)

            staged_deb_files.append((pkg_name, deb_scratch_path, pkg_info))
            verified_packages_summary[pkg_name] = {
                "version": pkg_info["version"],
                "pocket": pocket_name,
                "filename": pkg_info["filename"],
                "size": pkg_info["size"],
                "sha256": actual_deb_sha,
                "companion_runtime_packages": pkg_info.get("companion_runtime_packages", []),
                "exclusion_rationale": pkg_info.get("exclusion_rationale", "")
            }

        if check_only:
            return {
                "status": "VERIFIED_CHECK_ONLY",
                "snapshot_id": snapshot_id,
                "pockets": verified_pockets_summary,
                "packages": verified_packages_summary
            }

        # Stage 6: Safe Non-Root Extraction via dpkg-deb only
        for pkg_name, deb_path, pkg_info in staged_deb_files:
            safe_extract_deb(
                deb_path=deb_path,
                output_dir=abs_output,
                dpkg_deb_path=dpkg_deb_path
            )

        # Stage 7: Post-extraction Artifact & Prefix Verification with Link Containment
        staged_archives_summary = {}
        real_output_root = os.path.realpath(abs_output)

        for pkg_name, _, pkg_info in staged_deb_files:
            for art in pkg_info["required_artifacts"]:
                rel_art_path = art["path"]
                full_art_path = os.path.join(abs_output, rel_art_path)
                if not os.path.isfile(full_art_path):
                    raise SecurityError(f"Required artifact missing after extraction: {rel_art_path}")

                # Verify canonical containment (no escaping symlinks)
                real_art_path = os.path.realpath(full_art_path)
                if not real_art_path.startswith(real_output_root + "/") and real_art_path != real_output_root:
                    raise SecurityError(f"Extracted artifact escapes prefix: {rel_art_path} -> {real_art_path}")

                actual_art_size = os.path.getsize(full_art_path)
                if actual_art_size != art["size"]:
                    raise SecurityError(
                        f"Extracted artifact size mismatch for {rel_art_path}: got {actual_art_size}, expected {art['size']}"
                    )
                actual_art_sha = sha256_file(full_art_path)
                if actual_art_sha != art["sha256"]:
                    raise SecurityError(
                        f"Extracted artifact SHA256 mismatch for {rel_art_path}: got {actual_art_sha}, expected {art['sha256']}"
                    )
                staged_archives_summary[rel_art_path] = {
                    "package": pkg_name,
                    "size": actual_art_size,
                    "sha256": actual_art_sha
                }

            for hdr in pkg_info["required_headers"]:
                full_hdr_path = os.path.join(abs_output, hdr)
                if not os.path.isfile(full_hdr_path):
                    raise SecurityError(f"Required header missing after extraction: {hdr}")
                real_hdr_path = os.path.realpath(full_hdr_path)
                if not real_hdr_path.startswith(real_output_root + "/") and real_hdr_path != real_output_root:
                    raise SecurityError(f"Extracted header escapes prefix: {hdr} -> {real_hdr_path}")

        # Verify EXACT four static archives contract
        if set(staged_archives_summary.keys()) != REQUIRED_STATIC_ARCHIVES:
            raise SecurityError(
                f"Staged static archives do not match exact required closure {REQUIRED_STATIC_ARCHIVES}: got {set(staged_archives_summary.keys())}"
            )

        # Stage 8: Publish Receipt (Atomic write via temp file)
        receipt = {
            "receipt_schema": "iyi-bpf-dependency-receipt-v1",
            "status": "VERIFIED",
            "authenticated_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_id": snapshot_id,
            "base_url": base_url,
            "distribution": snapshot.get("distribution", "ubuntu"),
            "release": snapshot.get("release", "noble"),
            "release_version": snapshot.get("release_version", "24.04"),
            "architecture": snapshot.get("architecture", "amd64"),
            "signer_fingerprint": APPROVED_SIGNER_FINGERPRINT,
            "signer_key_id": APPROVED_KEY_ID,
            "keyring_path": resolved_keyring,
            "keyring_sha256": actual_keyring_sha,
            "pockets": verified_pockets_summary,
            "packages": verified_packages_summary,
            "staged_prefix": abs_output,
            "staged_static_archives": staged_archives_summary,
            "required_archives_count": len(staged_archives_summary)
        }

        receipt_dir = os.path.dirname(abs_receipt)
        os.makedirs(receipt_dir, mode=0o700, exist_ok=True)
        tmp_receipt = os.path.join(receipt_dir, f".tmp_receipt_{os.getpid()}.json")
        try:
            with open(tmp_receipt, "w", encoding="utf-8") as rf:
                json.dump(receipt, rf, indent=2)
                rf.write("\n")
            os.replace(tmp_receipt, abs_receipt)
        except Exception:
            if os.path.exists(tmp_receipt):
                os.unlink(tmp_receipt)
            raise

        return receipt

    finally:
        shutil.rmtree(temp_scratch, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authenticated lock consumer for Ubuntu BPF build dependencies."
    )
    parser.add_argument(
        "--lock",
        default="proof/bpf_dependencies.lock.json",
        help="Path to dependency lock JSON file (default: proof/bpf_dependencies.lock.json)"
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Target scratch directory prefix for extraction (must be owned, mode 0700)"
    )
    parser.add_argument(
        "--receipt",
        required=True,
        help="Path to output provenance receipt JSON"
    )
    parser.add_argument(
        "--keyring",
        default=None,
        help="Optional override for Ubuntu archive keyring path"
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Optional directory for caching or reading downloaded archives"
    )
    parser.add_argument(
        "--gpgv-path",
        default="/usr/bin/gpgv",
        help="Path to gpgv executable (default: /usr/bin/gpgv or PATH)"
    )
    parser.add_argument(
        "--dpkg-deb-path",
        default="/usr/bin/dpkg-deb",
        help="Path to dpkg-deb executable (default: /usr/bin/dpkg-deb or PATH)"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Verify lock and metadata signatures without extraction"
    )

    args = parser.parse_args()

    try:
        receipt = run_lock_consumer(
            lock_path=args.lock,
            output_prefix=args.output,
            receipt_path=args.receipt,
            keyring_path=args.keyring,
            cache_dir=args.cache_dir,
            gpgv_path=args.gpgv_path,
            dpkg_deb_path=args.dpkg_deb_path,
            check_only=args.check_only
        )
        print(f"[BPF_DEPENDENCIES_OK] Verified authenticated snapshot {receipt.get('snapshot_id')}")
        if not args.check_only:
            print(f"[BPF_DEPENDENCIES_OK] Staged 4 static archives in prefix: {receipt.get('staged_prefix')}")
            print(f"[BPF_DEPENDENCIES_OK] Wrote provenance receipt to: {args.receipt}")
        return 0
    except SecurityError as se:
        print(f"[BPF_DEPENDENCIES_SECURITY_ERROR] {se}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"[BPF_DEPENDENCIES_FATAL] Unexpected error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
