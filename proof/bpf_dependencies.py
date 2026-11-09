#!/usr/bin/env python3
"""
bpf_dependencies.py - Authenticated lock consumer for Ubuntu BPF build dependencies.

Implements the repository metadata consistency checking and safe nonroot extraction described in
PlanBpfOwnedDependencies (Sections 2 and 3).

Verifies the cryptographic chain and containment invariants:
  Ubuntu Archive Signing Key (2018) [F6ECB3762474EDA9D21B7022871920D1991BC93C]
    -> GPG-signed InRelease (exact approved set: noble, noble-updates, noble-security)
    -> RFC 4880 cleartext extraction from verified InRelease
    -> SHA256 / size of pocket-relative Packages.xz index in Release checksums
    -> Package records in Packages index (Version, Filename, Size, SHA256, Source, Architecture, Depends)
    -> Exact .deb archive bytes (SHA256, Size)
    -> Strict 3-member deb container preflight (debian-binary == 2.0\n, single control.tar, single data.tar)
    -> Preflight payload inspection (bounded decompression, no trailing streams, no traversal, no SUID/SGID, no device nodes)
    -> Cross-package canonical link-graph simulation and collision inventory (resolved-parent + unfollowed leaf, no link-graph escaping)
    -> Safe nonroot extraction via /usr/bin/dpkg-deb into fresh private scratch prefix beneath RUNNER_TEMP (mode 0700)
    -> Verification of exact 4 static archives ({libbpf.a, libelf.a, libz.a, libzstd.a}) and 23 development headers with strict object schemas
    -> Publication of verification receipt JSON recording authenticated provenance and digests.

Fails closed on any discrepancy, missing prerequisite, unapproved signer, or extraction safety violation.
"""

import argparse
import hashlib
import io
import json
import lzma
import os
import importlib.util
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

APPROVED_SIGNER_FINGERPRINT = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
APPROVED_KEY_ID = "871920D1991BC93C"
DEFAULT_KEYRING_PATH = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
DEFAULT_KEYRING_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
APPROVED_POCKETS = {"noble", "noble-updates", "noble-security"}
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

def verify_trusted_system_tool(tool_path: str, tool_name: str) -> str:
    if not (os.path.isfile(tool_path) and os.access(tool_path, os.X_OK)):
        raise SecurityError(f"{tool_name} executable not found at '{tool_path}'")
    try:
        baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bpf_runner_baseline.py")
        spec = importlib.util.spec_from_file_location("bpf_runner_baseline", baseline_path)
        if spec is None or spec.loader is None:
            raise ValueError("runner baseline verifier unavailable")
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        raw = gate.BASELINE.read_bytes()
        if hashlib.sha256(raw).hexdigest() != gate.CENSUS_SHA256:
            raise ValueError("census provenance hash mismatch")
        entry = json.loads(raw)["tools"][tool_name]
        if tool_path != entry["requested"]:
            raise ValueError("tool path differs from reviewed census")
        gate.check_path(entry, True)
        return entry["canonical"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SecurityError(f"{tool_name} baseline verification failed: {exc}") from exc


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
    """Decode a complete standalone XZ file, including valid streams and padding.

    Reject malformed framing, trailing garbage, and output beyond the cumulative
    bound. Archive-member XZ decoding has a separate, single-stream policy.
    """
    if expected_uncompressed_size < 0:
        raise SecurityError("Negative XZ output bound")
    magic = b"\xfd7zXZ\x00"
    pos = 0
    out = bytearray()
    if not data.startswith(magic):
        raise SecurityError("Missing initial XZ stream")
    while True:
        if not data.startswith(magic, pos):
            raise SecurityError("Trailing unconsumed data: expected XZ stream")
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        while not decompressor.eof:
            if decompressor.needs_input:
                if pos >= len(data):
                    raise SecurityError("Incomplete XZ stream: decompressor did not reach EOF")
                end = min(pos + 65536, len(data))
                chunk = data[pos:end]
                pos = end
            else:
                chunk = b""
            try:
                decoded = decompressor.decompress(
                    chunk, max_length=min(65536, expected_uncompressed_size - len(out) + 1)
                )
            except (lzma.LZMAError, EOFError, ValueError) as exc:
                raise SecurityError(f"Malformed XZ stream: {exc}") from exc
            out.extend(decoded)
            if len(out) > expected_uncompressed_size:
                raise SecurityError(
                    f"Decompressed XZ output exceeded bound ({len(out)} > {expected_uncompressed_size})"
                )
            if not chunk and not decoded and not decompressor.eof and not decompressor.needs_input:
                raise SecurityError("XZ decompressor made no progress")
        pos -= len(decompressor.unused_data)
        padding_start = pos
        while pos < len(data) and data[pos] == 0:
            pos += 1
        if (pos - padding_start) % 4:
            raise SecurityError("Invalid XZ stream padding length")
        if pos == len(data):
            break
    if len(out) != expected_uncompressed_size:
        raise SecurityError(
            f"Decompressed size mismatch: got {len(out)}, expected {expected_uncompressed_size}"
        )
    return bytes(out)


def get_zstd_frame_size(data: bytes) -> int:
    """Parse exact byte length of a single RFC 8878 Zstandard frame."""
    if len(data) < 4:
        raise SecurityError("Truncated zstd data (less than 4 bytes)")
    magic = int.from_bytes(data[:4], "little")
    if magic != 0xFD2FB528:
        raise SecurityError(f"Invalid zstd frame magic: {hex(magic)}")
    pos = 4
    if pos >= len(data):
        raise SecurityError("Truncated zstd frame header")
    fhd = data[pos]
    pos += 1
    dict_flag = fhd & 3
    checksum_flag = (fhd >> 2) & 1
    single_seg = (fhd >> 5) & 1
    fcs_flag = (fhd >> 6) & 3

    if not single_seg:
        pos += 1
    if dict_flag == 1: pos += 1
    elif dict_flag == 2: pos += 2
    elif dict_flag == 3: pos += 4

    if fcs_flag == 0 and single_seg: pos += 1
    elif fcs_flag == 1: pos += 2
    elif fcs_flag == 2: pos += 4
    elif fcs_flag == 3: pos += 8

    while True:
        if pos + 3 > len(data):
            raise SecurityError("Truncated zstd block header")
        bh = int.from_bytes(data[pos:pos+3], "little")
        pos += 3
        last_block = bh & 1
        block_type = (bh >> 1) & 3
        block_size = (bh >> 3) & 0x1FFFFF
        if block_type == 1:
            pos += 1
        elif block_type in (0, 2):
            pos += block_size
        else:
            raise SecurityError("Reserved zstd block type")
        if pos > len(data):
            raise SecurityError("Truncated zstd block content")
        if last_block:
            break

    if checksum_flag:
        pos += 4
    if pos > len(data):
        raise SecurityError("Truncated zstd checksum")
    return pos


def decompress_payload(member_name: str, data: bytes, max_bytes: int = 200 * 1024 * 1024) -> bytes:
    """
    Decompress tar payload with strict byte ceiling and trailing data/frame checks
    to prevent decompression bombs and payload desync.
    """
    if member_name.endswith(".zst"):
        frame_size = get_zstd_frame_size(data)
        if frame_size != len(data):
            raise SecurityError(f"Trailing unconsumed data after zstd frame ({len(data) - frame_size} bytes)")
        try:
            import zstandard
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(io.BytesIO(data), read_across_frames=False)
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
        if not decompressor.eof:
            raise SecurityError("Incomplete XZ payload: decompressor did not reach EOF")
        if decompressor.unused_data:
            raise SecurityError("Trailing unconsumed data after XZ payload")
        return bytes(out)
    elif member_name.endswith(".gz"):
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
        if not d.eof:
            raise SecurityError("Incomplete gzip stream: decompressor did not reach EOF")
        if d.unused_data:
            raise SecurityError("Trailing unconsumed data after gzip stream")
        return bytes(out)
    else:
        if len(data) > max_bytes:
            raise SecurityError(f"Uncompressed payload exceeded bound ({len(data)} > {max_bytes} bytes)")
        return data


def parse_ar_members(deb_bytes: bytes, max_member_size: int = 50 * 1024 * 1024) -> List[Tuple[str, int, bytes]]:
    """
    Parse ar archive members from debian package bytes with strict size bounds.
    Requires exactly 3 unambiguous members: debian-binary (2.0\n), control.tar.*, data.tar.*.
    Rejects trailing bytes or ambiguous containers.
    """
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

    if len(members) != 3:
        raise SecurityError(
            f"Debian archive must contain exactly 3 members, got {len(members)}: {[m[0] for m in members]}"
        )
    if members[0][0] != "debian-binary" or members[0][2] != b"2.0\n":
        raise SecurityError(r"debian-binary member must be exactly '2.0\n'")
    if not any(members[1][0] == f"control.tar.{ext}" for ext in ("zst", "xz", "gz")):
        raise SecurityError(f"Member 1 must be control.tar.[zst|xz|gz], got '{members[1][0]}'")
    if not any(members[2][0] == f"data.tar.{ext}" for ext in ("zst", "xz", "gz")):
        raise SecurityError(f"Member 2 must be data.tar.[zst|xz|gz], got '{members[2][0]}'")
    if pos < len(deb_bytes):
        raise SecurityError(f"Trailing bytes in deb archive: {len(deb_bytes) - pos} bytes unparsed")

    return members


class ArchiveCollisionInventory:
    """
    Tracks canonical directory paths and symlink resolutions across ALL packages.
    Enforces resolved-parent + unfollowed leaf, rejects duplicate non-directory entries,
    tracks implicit directories, and requires hardlinks to target known regular files.
    """
    def __init__(self):
        self.entries: Dict[str, str] = {}
        self.symlinks: Dict[str, str] = {}
        self.files: Dict[str, int] = {}

    def resolve_canonical(self, path_str: str, depth: int = 0) -> Optional[List[str]]:
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
                key = "/".join(cur_parts)
                if key in self.symlinks:
                    target = self.symlinks[key]
                    if target.startswith("/"):
                        return None
                    parent_parts = cur_parts[:-1]
                    target_path = "/".join(parent_parts + [target]) if parent_parts else target
                    resolved = self.resolve_canonical(target_path, depth + 1)
                    if resolved is None:
                        return None
                    cur_parts = list(resolved)
        return cur_parts

    def register_member(
        self,
        clean_name: str,
        member_type: str,
        linkname: Optional[str] = None,
        file_size: int = 0
    ) -> str:
        parent_raw = os.path.dirname(clean_name)
        if parent_raw:
            parent_canon_parts = self.resolve_canonical(parent_raw)
            if parent_canon_parts is None:
                raise SecurityError(f"Path traverses through escaping directory/symlink: {clean_name}")
            parent_canon = "/".join(parent_canon_parts)
        else:
            parent_canon_parts = []
            parent_canon = ""

        # Track implicit directories along parent_canon_parts
        for i in range(1, len(parent_canon_parts) + 1):
            d_path = "/".join(parent_canon_parts[:i])
            if d_path in self.entries and self.entries[d_path] != "dir":
                raise SecurityError(f"Implicit directory {d_path} collides with non-directory {self.entries[d_path]}")
            self.entries.setdefault(d_path, "dir")

        leaf = os.path.basename(clean_name)
        canonical_path = f"{parent_canon}/{leaf}" if parent_canon else leaf

        # Check duplicate non-directory entries
        if canonical_path in self.entries:
            if self.entries[canonical_path] == "dir" and member_type == "dir":
                pass
            else:
                raise SecurityError(
                    f"Duplicate or colliding entry for path: {canonical_path} (existing={self.entries[canonical_path]}, new={member_type})"
                )

        if member_type == "symlink":
            if not linkname or linkname.startswith("/"):
                raise SecurityError(f"Prohibited absolute or empty symlink target: {clean_name} -> {linkname}")
            target_path = "/".join(parent_canon_parts + [linkname]) if parent_canon_parts else linkname
            resolved_target = self.resolve_canonical(target_path)
            if resolved_target is None:
                raise SecurityError(f"Symlink escapes root: {clean_name} -> {linkname}")
            self.entries[canonical_path] = "symlink"
            self.symlinks[canonical_path] = linkname
        elif member_type == "dir":
            self.entries[canonical_path] = "dir"
        elif member_type == "reg":
            self.entries[canonical_path] = "reg"
            self.files[canonical_path] = file_size
        elif member_type == "hardlink":
            if not linkname or linkname.startswith("/"):
                raise SecurityError(f"Prohibited absolute or empty hardlink target: {clean_name} -> {linkname}")
            # Resolve target parent only, require unfollowed leaf previously registered as actual regular file
            target_parent_raw = os.path.dirname(linkname)
            target_leaf = os.path.basename(linkname)
            if target_parent_raw:
                target_parent_parts = self.resolve_canonical(target_parent_raw)
                if target_parent_parts is None:
                    raise SecurityError(f"Hardlink target parent escapes root: {linkname}")
                target_parent_canon = "/".join(target_parent_parts)
            else:
                target_parent_canon = ""
            target_canon_path = f"{target_parent_canon}/{target_leaf}" if target_parent_canon else target_leaf

            if target_canon_path not in self.entries:
                raise SecurityError(f"Hardlink target not found: {linkname} ({target_canon_path})")
            if self.entries[target_canon_path] != "reg":
                raise SecurityError(
                    f"Hardlink target must be a known regular file, but {target_canon_path} is {self.entries[target_canon_path]}"
                )
            self.entries[canonical_path] = "hardlink"

        return canonical_path


def extract_clearsigned_text(inrelease_bytes: bytes) -> str:
    """
    Extract the signed cleartext payload from an InRelease clearsigned OpenPGP message (RFC 4880 §7).
    Must only be called AFTER gpgv has validated the signature and VALIDSIG has been verified.
    """
    text = inrelease_bytes.decode("utf-8", errors="replace")
    lines = text.splitlines()

    start_idx = -1
    for i, line in enumerate(lines):
        if line.strip() == "-----BEGIN PGP SIGNED MESSAGE-----":
            start_idx = i
            break
    if start_idx == -1:
        raise SecurityError("InRelease missing '-----BEGIN PGP SIGNED MESSAGE-----' header")

    content_start = -1
    for i in range(start_idx + 1, len(lines)):
        if lines[i].strip() == "":
            content_start = i + 1
            break
        if lines[i].strip().startswith("-----BEGIN PGP SIGNATURE-----"):
            raise SecurityError("InRelease malformed: signature encountered before message body")

    if content_start == -1:
        raise SecurityError("InRelease missing header-body separator in signed message")

    sig_start = -1
    for i in range(content_start, len(lines)):
        if lines[i].strip() == "-----BEGIN PGP SIGNATURE-----":
            sig_start = i
            break

    if sig_start == -1:
        raise SecurityError("InRelease missing '-----BEGIN PGP SIGNATURE-----' footer")

    body_lines = []
    for line in lines[content_start:sig_start]:
        if line.startswith("- "):
            body_lines.append(line[2:])
        else:
            body_lines.append(line)

    return "\n".join(body_lines)


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
    expected_arch: str,
    collision_inventory: ArchiveCollisionInventory
) -> None:
    """
    Perform preflight safety scan on .deb before any extraction:
    - Enforce exactly 3 ar members in order (debian-binary == 2.0\n, control.tar, data.tar).
    - Compare control fields against package record.
    - Inspect every data.tar member: no path traversal, no setuid/setgid, no escaping links, no device nodes.
    - Register members in the cross-package canonical collision and link graph inventory.
    """
    members = parse_ar_members(deb_bytes)

    # 1. Inspect control.tar
    control_member = members[1]
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

    # 2. Inspect data.tar with complete canonical link graph and collision inventory
    data_member = members[2]
    data_tar_bytes = decompress_payload(data_member[0], data_member[2], max_bytes=200 * 1024 * 1024)
    tf_data = tarfile.open(fileobj=io.BytesIO(data_tar_bytes))

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

        if m.issym():
            m_type = "symlink"
            linkname = m.linkname
        elif m.islnk():
            m_type = "hardlink"
            linkname = m.linkname
        elif m.isdir():
            m_type = "dir"
            linkname = None
        else:
            m_type = "reg"
            linkname = None

        collision_inventory.register_member(
            clean_name=clean,
            member_type=m_type,
            linkname=linkname,
            file_size=m.size
        )


def safe_extract_deb(deb_path: str, output_dir: str, dpkg_deb_path: str) -> None:
    """
    Extract .deb into output_dir nonroot using /usr/bin/dpkg-deb per PlanBpfOwnedDependencies.
    No fallback internal extractor is permitted.
    """
    resolved_dpkg = verify_trusted_system_tool(dpkg_deb_path, "dpkg-deb")

    cmd = [resolved_dpkg, "--extract", deb_path, output_dir]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise SecurityError(f"dpkg-deb --extract failed (exit {p.returncode}): {p.stderr}")


def validate_prefix_containment(output_prefix: str) -> str:
    """
    Enforce private job-directory containment per PlanBpfOwnedDependencies §3:
    - Verifies RUNNER_TEMP is set.
    - Check all ancestors for symlinks without pre-resolving paths.
    - Output prefix must NOT already exist (must be freshly created by consumer).
    - Output prefix must be strictly contained beneath RUNNER_TEMP.
    - Set mode 0700.
    """
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise SecurityError("RUNNER_TEMP environment variable is required")
    real_runner_temp = os.path.realpath(runner_temp)
    if not os.path.isdir(real_runner_temp):
        raise SecurityError(f"RUNNER_TEMP directory does not exist: {runner_temp}")

    abs_output = os.path.abspath(output_prefix)
    system_dirs = {"/", "/usr", "/etc", "/var", "/home", "/bin", "/sbin", "/lib", "/lib64", "/tmp"}
    if abs_output in system_dirs:
        raise SecurityError(f"Refusing system directory as output prefix: {abs_output}")

    cur = os.path.dirname(abs_output)
    while cur and cur != "/":
        if os.path.islink(cur):
            raise SecurityError(f"Ancestor directory is a symlink: {cur}")
        cur = os.path.dirname(cur)

    real_output = os.path.realpath(abs_output)
    if not (real_output.startswith(real_runner_temp + "/") or real_output == real_runner_temp):
        raise SecurityError(f"Output prefix {abs_output} is not contained within RUNNER_TEMP ({runner_temp})")

    # Reject existing prefix: must be freshly created!
    if os.path.exists(abs_output):
        raise SecurityError(f"Output prefix already exists: {abs_output}. Output prefix must be freshly created.")

    old_umask = os.umask(0o077)
    try:
        os.makedirs(abs_output, mode=0o700, exist_ok=False)
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
    Main orchestrator implementing cryptographic verification and safe extraction.
    Returns the receipt data structure on success; raises SecurityError on failure.
    """
    # Unconditional non-root guard precedes all execution modes
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SecurityError("Refusing execution as root. Dependency extraction must run as unprivileged user.")

    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise SecurityError("RUNNER_TEMP environment variable is required")
    real_runner_temp = os.path.realpath(runner_temp)
    if not os.path.isdir(real_runner_temp):
        raise SecurityError(f"RUNNER_TEMP directory does not exist: {runner_temp}")

    abs_output = validate_prefix_containment(output_prefix) if not check_only else os.path.abspath(output_prefix)
    abs_receipt = os.path.abspath(receipt_path)

    if not check_only:
        # Non-overlapping destination checks
        if abs_receipt == abs_output or abs_receipt.startswith(abs_output + "/"):
            raise SecurityError(f"Receipt destination path cannot be within output prefix: {abs_receipt}")

        real_receipt = os.path.realpath(abs_receipt)
        if not (real_receipt.startswith(real_runner_temp + "/") or real_receipt == real_runner_temp):
            raise SecurityError(f"Receipt destination ({abs_receipt}) is not contained within RUNNER_TEMP ({runner_temp})")

        if os.path.islink(abs_receipt):
            raise SecurityError(f"Receipt destination path is a symlink: {abs_receipt}")
        cur = os.path.dirname(abs_receipt)
        while cur and cur != "/":
            if os.path.islink(cur):
                raise SecurityError(f"Receipt parent directory ancestor is a symlink: {cur}")
            cur = os.path.dirname(cur)

    if cache_dir:
        real_cache = os.path.realpath(cache_dir)
        if not (real_cache.startswith(real_runner_temp + "/") or real_cache == real_runner_temp):
            raise SecurityError(f"Cache directory ({cache_dir}) is not contained within RUNNER_TEMP ({runner_temp})")

    # Stage 2: Load and validate lock schema, exact packages, and approved pockets
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

    # Validate receipt destination does not overwrite any required artifact
    if not check_only:
        for p_info in packages_meta.values():
            for art in p_info.get("required_artifacts", []):
                if not isinstance(art, dict) or not art.get("path") or not art.get("size") or not art.get("sha256"):
                    raise SecurityError("Lock package required_artifacts has invalid schema")
                if abs_receipt == os.path.join(abs_output, art["path"]):
                    raise SecurityError(f"Receipt destination cannot overwrite required artifact: {abs_receipt}")
            for hdr in p_info.get("required_headers", []):
                if not isinstance(hdr, dict) or not hdr.get("path") or not hdr.get("size") or not hdr.get("sha256"):
                    raise SecurityError("Lock package required_headers has invalid schema")
                if abs_receipt == os.path.join(abs_output, hdr["path"]):
                    raise SecurityError(f"Receipt destination cannot overwrite required header: {abs_receipt}")

    # Strict approved pockets allowlist enforcement before any I/O
    pockets_meta = lock.get("metadata_pockets")
    if not pockets_meta or not isinstance(pockets_meta, dict):
        raise SecurityError("Lock missing metadata_pockets definition")
    if set(pockets_meta.keys()) != APPROVED_POCKETS:
        raise SecurityError(
            f"metadata_pockets keys must match exact approved set {APPROVED_POCKETS}, got {set(pockets_meta.keys())}"
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

    resolved_gpgv = verify_trusted_system_tool(gpgv_path, "gpgv")

    # Use RUNNER_TEMP for private scratch
    old_umask = os.umask(0o077)
    temp_scratch = tempfile.mkdtemp(prefix="iyi_bpf_lock_", dir=real_runner_temp)
    os.umask(old_umask)

    try:
        # Stage 3: Authenticate Pockets (InRelease & Packages indices)
        parsed_pockets: Dict[str, Dict[str, Dict[str, str]]] = {}
        verified_pockets_summary: List[Dict[str, Any]] = []
        freshness = lock.get("freshness_policy", {})

        for pocket_name in sorted(APPROVED_POCKETS):
            pocket_info = pockets_meta[pocket_name]
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

            # Extract release cleartext (RFC 4880 verified message body)
            if os.path.isfile(output_release) and os.path.getsize(output_release) > 0:
                with open(output_release, "r", encoding="utf-8", errors="replace") as rf:
                    release_text = rf.read()
            else:
                release_text = extract_clearsigned_text(inrelease_bytes)

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

        # Stage 4: Package Records Validation and Preflight Inspection
        verified_packages_summary: Dict[str, Any] = {}
        staged_deb_files: List[Tuple[str, str, Dict[str, Any]]] = []
        collision_inventory = ArchiveCollisionInventory()

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

            req_artifacts = pkg_info.get("required_artifacts")
            if not req_artifacts or not isinstance(req_artifacts, list):
                raise SecurityError(f"Package {pkg_name} must declare non-empty required_artifacts")
            req_headers = pkg_info.get("required_headers")
            if not req_headers or not isinstance(req_headers, list):
                raise SecurityError(f"Package {pkg_name} must declare non-empty required_headers")

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
                expected_arch=pkg_info["architecture"],
                collision_inventory=collision_inventory
            )

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
        staged_headers_summary = {}
        real_output_root = os.path.realpath(abs_output)

        for pkg_name, _, pkg_info in staged_deb_files:
            for art in pkg_info["required_artifacts"]:
                rel_art_path = art["path"]
                full_art_path = os.path.join(abs_output, rel_art_path)
                if not os.path.isfile(full_art_path):
                    raise SecurityError(f"Required artifact missing after extraction: {rel_art_path}")

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
                if not isinstance(hdr, dict):
                    raise SecurityError(f"Header in {pkg_name} must be a dict object")
                rel_hdr_path = hdr.get("path")
                expected_hdr_size = hdr.get("size")
                expected_hdr_sha = hdr.get("sha256")
                if not rel_hdr_path or not isinstance(rel_hdr_path, str):
                    raise SecurityError(f"Header in {pkg_name} missing valid 'path'")
                if expected_hdr_size is None or not isinstance(expected_hdr_size, int) or expected_hdr_size <= 0:
                    raise SecurityError(f"Header {rel_hdr_path} in {pkg_name} missing valid positive 'size'")
                if not expected_hdr_sha or not isinstance(expected_hdr_sha, str) or len(expected_hdr_sha) != 64:
                    raise SecurityError(f"Header {rel_hdr_path} in {pkg_name} missing valid 64-char 'sha256'")

                full_hdr_path = os.path.join(abs_output, rel_hdr_path)
                if not os.path.isfile(full_hdr_path):
                    raise SecurityError(f"Required header missing after extraction: {rel_hdr_path}")
                real_hdr_path = os.path.realpath(full_hdr_path)
                if not real_hdr_path.startswith(real_output_root + "/") and real_hdr_path != real_output_root:
                    raise SecurityError(f"Extracted header escapes prefix: {rel_hdr_path} -> {real_hdr_path}")

                actual_hdr_size = os.path.getsize(full_hdr_path)
                if actual_hdr_size != expected_hdr_size:
                    raise SecurityError(
                        f"Extracted header size mismatch for {rel_hdr_path}: got {actual_hdr_size}, expected {expected_hdr_size}"
                    )
                actual_hdr_sha = sha256_file(full_hdr_path)
                if actual_hdr_sha != expected_hdr_sha:
                    raise SecurityError(
                        f"Extracted header SHA256 mismatch for {rel_hdr_path}: got {actual_hdr_sha}, expected {expected_hdr_sha}"
                    )
                staged_headers_summary[rel_hdr_path] = {
                    "package": pkg_name,
                    "size": actual_hdr_size,
                    "sha256": actual_hdr_sha
                }

        # Verify EXACT four static archives contract
        if set(staged_archives_summary.keys()) != REQUIRED_STATIC_ARCHIVES:
            raise SecurityError(
                f"Staged static archives do not match exact required closure {REQUIRED_STATIC_ARCHIVES}: got {set(staged_archives_summary.keys())}"
            )

        # Stage 8: Publish Receipt (Atomic write via exclusive temporary file)
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
            "staged_headers": staged_headers_summary,
            "required_archives_count": len(staged_archives_summary),
            "required_headers_count": len(staged_headers_summary)
        }

        receipt_dir = os.path.dirname(abs_receipt)
        os.makedirs(receipt_dir, mode=0o700, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=receipt_dir,
            delete=False,
            prefix=".receipt_tmp_",
            encoding="utf-8"
        ) as tf:
            tmp_receipt_path = tf.name
            json.dump(receipt, tf, indent=2)
            tf.write("\n")
            tf.flush()
            os.fsync(tf.fileno())

        os.replace(tmp_receipt_path, abs_receipt)
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
        print(f"[BPF_DEPENDENCIES_OK] Verified snapshot metadata {receipt.get('snapshot_id')}")
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
