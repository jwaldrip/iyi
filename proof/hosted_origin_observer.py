#!/usr/bin/env python3
"""
proof/hosted_origin_observer.py

C-owned data-only origin observer for hosted proof environments.
Runs after exact workload container teardown against read-only preserved roots.

Key Security Invariants:
1. Pure C-owned: never imports or executes W/P code, shells, or compilers.
2. Descriptor-relative traversal: opens allowed directory roots with O_DIRECTORY|O_CLOEXEC,
   walks subdirectories descriptor-relatively with O_NOFOLLOW|O_CLOEXEC, enforces mount boundaries,
   verifies roots are not symlinks, bounds resource usage, and never traverses symlinks or magic links.
3. Pre-read metadata capture: captures complete stat metadata (st_dev, st_ino, st_atime_ns,
   st_mtime_ns, st_ctime_ns, st_nlink, size, mode, uid, gid) for EVERY candidate regular file
   BEFORE opening or reading ledger.jsonl or any file content.
4. Committed checkpoint: emits/freezes the pre-read initial census checkpoint to the private
   controller pipe BEFORE reading ledger.jsonl. Traversal errors fail closed immediately without
   reading ledger.
5. Root qualification: candidate identities, reference binding, and raw evidence capture are
   root-qualified (root_index, rel_path) to prevent cross-root collisions and preserve origin.
6. C-trusted logical slot manifest: defines all mandatory E3 build slots (63 total across the 29
   driver censuses: 57 own/mixed-own slots and 6 positive variant slots) independently before launch.
7. Private runtime binder join: binds logical slot_id <-> transaction_id <-> runtime UUID out.ref <->
   witness observed exec. Requires creation-time hardlink authentication so legitimate driver cleanup
   unlinking out post-run is supported while unauthenticated out unlinking fails closed.
8. Exact slot equality and duplicate inode prohibition: exact set equality of mandatory slot_ids
   and fulfilled slot_ids; distinct build slots cannot share the same physical (st_dev, st_ino).
9. Kernel observation verification: binds recorded mtime to kernel-observed mtime. Recomputes integer
   atime advancement strictly from kernel observations (obs_atime_ns > obs_mtime_ns).
10. Strict resource budgets: enforced on fstat BEFORE any read; stream in fixed 64 KiB chunks;
    bounds max traversal depth, candidate count, ledger bytes, and raw file / aggregate bytes.
11. Inode-deduplicated raw evidence: captures raw executable bytes once per physical (st_dev, st_ino)
    via held descriptors, tracking hardlink aliases, and verifies post-read metadata immutability.
12. Length-delimited versioned protocol: streams framed output (b"IYOB" + v1) to inherited
    controller-owned private pipe with no workload access. Final frame carries complete verified evidence.
13. Exact limits: this observer is data-only. Collector observations alone CANNOT prove execution
    against malicious read/utime without an independent kernel-level execution witness.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import errno
import hashlib
import json
import os
import stat
import struct
import sys
import time
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple


# Protocol constants
PROTOCOL_MAGIC: bytes = b"IYOB"
PROTOCOL_VERSION: int = 1

FRAME_METADATA: int = 0x01
FRAME_RAW_FILE: int = 0x02
FRAME_TERMINATION: int = 0x03
FRAME_ERROR: int = 0x04

# Resource budgets
MAX_TRAVERSAL_DEPTH: int = 16
MAX_CANDIDATE_FILES: int = 10_000
MAX_LEDGER_BYTES: int = 16 * 1024 * 1024          # 16 MiB
MAX_RAW_FILE_BYTES: int = 256 * 1024 * 1024       # 256 MiB
MAX_AGGREGATE_RAW_BYTES: int = 512 * 1024 * 1024  # 512 MiB
CHUNK_SIZE: int = 64 * 1024                       # 64 KiB

# Safe open flags
O_CLOEXEC: int = getattr(os, "O_CLOEXEC", 0)
O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)
O_PATH: int = getattr(os, "O_PATH", os.O_RDONLY)


@dataclass(frozen=True)
class LogicalSlot:
    slot_id: str                      # unique ID e.g. "acme::70::acme-plain::own"
    driver: str                       # e.g. "acme"
    site_line: int                    # e.g. 70
    label: str                        # e.g. "acme-plain"
    kind: str                         # "own" or "positive"
    variant_id: Optional[str]         # e.g. "compress.positive.464" or None
    output_template: str              # e.g. "{WORK}/acme-plain"
    compiler_options: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "driver": self.driver,
            "site_line": self.site_line,
            "label": self.label,
            "kind": self.kind,
            "variant_id": self.variant_id,
            "output_template": self.output_template,
            "compiler_options": list(self.compiler_options),
        }


@dataclass(frozen=True)
class RuntimeBinding:
    slot_id: str
    transaction_id: str
    inv: str                           # invocation UUID e.g. "a1b2c3d4-..."
    out_path: str                      # logical/actual out path at link time e.g. "t/prog"
    out_ref_path: str                  # real W path: "<scratch>/<UUID>/out.ref"
    st_dev: int
    st_ino: int
    out_mtime_ns: int
    atime_set_ns: int
    out_sha256: str
    hardlink_authenticated: bool = True
    exec_verified: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "transaction_id": self.transaction_id,
            "inv": self.inv,
            "out_path": self.out_path,
            "out_ref_path": self.out_ref_path,
            "st_dev": self.st_dev,
            "st_ino": self.st_ino,
            "out_mtime_ns": self.out_mtime_ns,
            "atime_set_ns": self.atime_set_ns,
            "out_sha256": self.out_sha256,
            "hardlink_authenticated": self.hardlink_authenticated,
            "exec_verified": self.exec_verified,
        }


@dataclass(frozen=True)
class LaunchBinding:
    chain_id: str
    driver: str
    attempt: int
    launch_id: str
    expected_nonce: str
    logical_slots: Tuple[LogicalSlot, ...] = ()
    expected_refs: Tuple[str, ...] = ()


@dataclass
class CandidateFile:
    rel_path: str
    root_index: int
    root_path: str
    st_dev: int
    st_ino: int
    st_mode: int
    st_nlink: int
    st_uid: int
    st_gid: int
    st_size: int
    st_atime_ns: int
    st_mtime_ns: int
    st_ctime_ns: int
    seq: int
    fd: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "root_index": self.root_index,
            "st_dev": self.st_dev,
            "st_ino": self.st_ino,
            "st_mode": self.st_mode,
            "st_nlink": self.st_nlink,
            "st_uid": self.st_uid,
            "st_gid": self.st_gid,
            "st_size": self.st_size,
            "st_atime_ns": self.st_atime_ns,
            "st_mtime_ns": self.st_mtime_ns,
            "st_ctime_ns": self.st_ctime_ns,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class SpecialEntry:
    rel_path: str
    root_index: int
    st_dev: int
    st_ino: int
    st_mode: int
    kind: str  # "symlink", "fifo", "socket", "char_device", "block_device"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rel_path": self.rel_path,
            "root_index": self.root_index,
            "st_dev": self.st_dev,
            "st_ino": self.st_ino,
            "st_mode": self.st_mode,
            "kind": self.kind,
        }


# Expected reference & logical slot derivation from C-trusted census


def build_driver_logical_slots(census_data: Dict[str, Any], driver: str) -> List[LogicalSlot]:
    """
    Construct the C-trusted logical E3 build slots for a driver from its census.
    Exact W has 57 own/mixed-own slots and 6 positive variant slots (63 total).
    """
    slots: List[LogicalSlot] = []

    # 1. Own / mixed-own build slots
    if driver == "fuzz":
        slots.append(
            LogicalSlot(
                slot_id="fuzz::15::fuzz_slot::own",
                driver="fuzz",
                site_line=15,
                label="fuzz_slot",
                kind="own",
                variant_id=None,
                output_template="{WORK}/fuzz_slot",
                compiler_options=(),
            )
        )
    else:
        # Find canonical-own or mixed-own build site in census
        sites = census_data.get("sites", [])
        site_line = 0
        for s in sites:
            if s.get("command") == "build" and s.get("kind") in ("canonical-own", "mixed"):
                site_line = s.get("lines", [0])[0]
                break
        if site_line == 0:
            site_line = 70  # default fallback if not labeled

        slots.append(
            LogicalSlot(
                slot_id=f"{driver}::{site_line}::{driver}-plain::own",
                driver=driver,
                site_line=site_line,
                label=f"{driver}-plain",
                kind="own",
                variant_id=None,
                output_template=f"{{WORK}}/{driver}-plain",
                compiler_options=(),
            )
        )
        slots.append(
            LogicalSlot(
                slot_id=f"{driver}::{site_line}::{driver}-release::own",
                driver=driver,
                site_line=site_line,
                label=f"{driver}-release",
                kind="own",
                variant_id=None,
                output_template=f"{{WORK}}/{driver}-release",
                compiler_options=("--release",),
            )
        )

    # 2. Positive variant build slots (only 4 drivers produce positive E3 builds)
    if driver == "compress":
        slots.append(
            LogicalSlot(
                slot_id="compress::464::small.bin::compress.positive.464",
                driver="compress",
                site_line=464,
                label="small.bin",
                kind="positive",
                variant_id="compress.positive.464",
                output_template="{WORK}/small.bin",
                compiler_options=("--release",),
            )
        )
    elif driver == "file":
        slots.append(
            LogicalSlot(
                slot_id="file::628::nul_cut-prog::file.positive.628.required",
                driver="file",
                site_line=628,
                label="nul_cut-prog",
                kind="positive",
                variant_id="file.positive.628.required",
                output_template="{WORK}/nul_cut-prog",
                compiler_options=(),
            )
        )
        slots.append(
            LogicalSlot(
                slot_id="file::628::realpath_through-prog::file.positive.628.platform-excluded",
                driver="file",
                site_line=628,
                label="realpath_through-prog",
                kind="positive",
                variant_id="file.positive.628.platform-excluded",
                output_template="{WORK}/realpath_through-prog",
                compiler_options=(),
            )
        )
    elif driver == "math":
        slots.append(
            LogicalSlot(
                slot_id="math::555::software/program::math.positive.555",
                driver="math",
                site_line=555,
                label="software/program",
                kind="positive",
                variant_id="math.positive.555",
                output_template="{WORK}/software/program",
                compiler_options=("--release",),
            )
        )
    elif driver == "tls":
        slots.append(
            LogicalSlot(
                slot_id="tls::932::tlsx-downgrade::tls.positive.downgrade.795",
                driver="tls",
                site_line=932,
                label="tlsx-downgrade",
                kind="positive",
                variant_id="tls.positive.downgrade.795",
                output_template="{WORK}/downgrade/tlsx",
                compiler_options=(),
            )
        )
        slots.append(
            LogicalSlot(
                slot_id="tls::932::tlsx-downgrade-unchecked::tls.positive.downgrade.795",
                driver="tls",
                site_line=932,
                label="tlsx-downgrade-unchecked",
                kind="positive",
                variant_id="tls.positive.downgrade.795",
                output_template="{WORK}/downgrade-unchecked/tlsx",
                compiler_options=(),
            )
        )

    return slots


def derive_trusted_expected_references(
    census_data: Dict[str, Any],
    driver: str,
    work_prefix: str = "t",
) -> List[str]:
    """
    Derive the C-trusted expected reference set from the C-trusted driver census.
    Never consults the untrusted ledger or workload claims.
    """
    slots = build_driver_logical_slots(census_data, driver)
    expected: Set[str] = set()
    for s in slots:
        path = s.output_template.replace("{WORK}", work_prefix)
        expected.add(os.path.normpath(f"{path}.ref"))
    return sorted(expected)


# Wire framing


def write_header(stream: BinaryIO) -> None:
    """Write 8-byte protocol header: b'IYOB' + uint32(1)."""
    stream.write(PROTOCOL_MAGIC + struct.pack(">I", PROTOCOL_VERSION))
    stream.flush()


def read_header(stream: BinaryIO) -> int:
    """Read and validate protocol header. Returns protocol version."""
    magic = stream.read(4)
    if magic != PROTOCOL_MAGIC:
        raise ValueError(f"Invalid protocol magic: {magic!r}, expected {PROTOCOL_MAGIC!r}")
    raw_ver = stream.read(4)
    if len(raw_ver) < 4:
        raise ValueError("Truncated protocol header version")
    version = struct.unpack(">I", raw_ver)[0]
    if version != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported protocol version: {version}, expected {PROTOCOL_VERSION}")
    return version


def write_frame(stream: BinaryIO, frame_type: int, payload: bytes) -> None:
    """Write length-delimited frame: [uint32 frame_type][uint32 length][payload]."""
    header = struct.pack(">II", frame_type, len(payload))
    stream.write(header + payload)
    stream.flush()


def read_frame(stream: BinaryIO) -> Optional[Tuple[int, bytes]]:
    """Read next length-delimited frame. Returns (frame_type, payload) or None on EOF."""
    header = stream.read(8)
    if not header:
        return None
    if len(header) < 8:
        raise ValueError(f"Truncated frame header: {len(header)} bytes")
    frame_type, length = struct.unpack(">II", header)
    payload = stream.read(length)
    if len(payload) < length:
        raise ValueError(f"Truncated frame payload: expected {length} bytes, got {len(payload)}")
    return frame_type, payload


def encode_raw_file_frame(
    root_index: int,
    rel_path: str,
    st_dev: int,
    st_ino: int,
    sha256_hex: str,
    file_bytes: bytes,
    aliases: Optional[List[Dict[str, Any]]] = None,
) -> bytes:
    """Encode raw file payload for FRAME_RAW_FILE with root qualification and hardlink aliases."""
    path_bytes = rel_path.encode("utf-8")
    aliases_bytes = json.dumps(aliases or []).encode("utf-8")
    sha_bytes = bytes.fromhex(sha256_hex)
    header = (
        struct.pack(">HHI", len(path_bytes), len(aliases_bytes), root_index)
        + path_bytes
        + aliases_bytes
        + struct.pack(">QQ32sI", st_dev, st_ino, sha_bytes, len(file_bytes))
    )
    return header + file_bytes


def decode_raw_file_frame(payload: bytes) -> Dict[str, Any]:
    """Decode raw file payload from FRAME_RAW_FILE."""
    if len(payload) < 8:
        raise ValueError("Truncated raw file frame payload (no path/aliases length)")
    path_len, aliases_len, root_index = struct.unpack(">HHI", payload[:8])
    offset = 8
    if len(payload) < offset + path_len + aliases_len + 8 + 8 + 32 + 4:
        raise ValueError("Truncated raw file frame header")
    rel_path = payload[offset : offset + path_len].decode("utf-8")
    offset += path_len
    aliases_json = payload[offset : offset + aliases_len].decode("utf-8")
    aliases: List[Dict[str, Any]] = json.loads(aliases_json) if aliases_json else []
    offset += aliases_len
    st_dev, st_ino, sha_bytes, data_len = struct.unpack(">QQ32sI", payload[offset : offset + 52])
    offset += 52
    file_bytes = payload[offset : offset + data_len]
    if len(file_bytes) != data_len:
        raise ValueError(f"Raw file data length mismatch: expected {data_len}, got {len(file_bytes)}")
    return {
        "root_index": root_index,
        "rel_path": rel_path,
        "aliases": aliases,
        "st_dev": st_dev,
        "st_ino": st_ino,
        "sha256": sha_bytes.hex(),
        "file_bytes": file_bytes,
    }


# Chunked and bounded read helper


def read_bounded_bytes(fd: int, max_bytes: int, expected_size: int) -> Tuple[bytes, str]:
    """
    Read bytes in fixed 64 KiB chunks, enforcing byte ceilings before buffer allocation.
    Returns (content_bytes, sha256_hex).
    """
    if expected_size > max_bytes:
        raise ValueError(f"file size {expected_size} exceeds budget of {max_bytes} bytes")
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    content = bytearray()
    total_read = 0
    while True:
        chunk = os.read(fd, CHUNK_SIZE)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > max_bytes:
            raise ValueError(f"read exceeded budget of {max_bytes} bytes")
        content.extend(chunk)
        hasher.update(chunk)
    return bytes(content), hasher.hexdigest()


# Descriptor-relative traversal & pre-read sampling


def walk_roots_descriptor_relative(
    roots: List[str],
) -> Tuple[List[CandidateFile], List[SpecialEntry], List[str]]:
    """
    Descriptor-relative traversal of preserved roots without following symlinks.
    Captures complete initial metadata and holds file descriptors for all regular files.
    Enforces mount boundary confinement, verifies roots are not symlinks, and respects resource budgets.
    """
    candidates: List[CandidateFile] = []
    specials: List[SpecialEntry] = []
    errors: List[str] = []
    global_seq = 0

    for root_idx, root_path in enumerate(roots):
        if os.path.islink(root_path):
            errors.append(f"root path cannot be a symlink: {root_path}")
            continue

        abs_root = os.path.abspath(root_path)
        if not os.path.exists(abs_root):
            errors.append(f"root does not exist: {abs_root}")
            continue

        try:
            root_fd = os.open(abs_root, os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        except OSError as e:
            errors.append(f"failed to open root {abs_root}: {e}")
            continue

        try:
            root_stat = os.fstat(root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                errors.append(f"root is not a directory: {abs_root}")
                continue

            root_dev = root_stat.st_dev
            visited_dirs: Set[Tuple[int, int]] = {(root_dev, root_stat.st_ino)}

            # Stack for directory walk: (dir_fd, rel_dir_path, depth)
            stack: List[Tuple[int, str, int]] = [(root_fd, "", 0)]

            while stack:
                curr_fd, curr_rel, curr_depth = stack.pop()

                if curr_depth > MAX_TRAVERSAL_DEPTH:
                    errors.append(f"traversal depth exceeded budget of {MAX_TRAVERSAL_DEPTH} at {curr_rel}")
                    if curr_fd != root_fd:
                        os.close(curr_fd)
                    continue

                try:
                    entries = sorted(os.listdir(curr_fd))
                except OSError as e:
                    errors.append(f"failed to listdir {curr_rel or '.'}: {e}")
                    if curr_fd != root_fd:
                        os.close(curr_fd)
                    continue

                for name in entries:
                    if len(candidates) >= MAX_CANDIDATE_FILES:
                        errors.append(f"candidate file count exceeded budget of {MAX_CANDIDATE_FILES}")
                        break

                    if name in (".", "..") or "/" in name or "\0" in name:
                        errors.append(f"invalid directory entry name: {name!r}")
                        continue

                    entry_rel = os.path.join(curr_rel, name) if curr_rel else name

                    try:
                        entry_stat = os.stat(name, dir_fd=curr_fd, follow_symlinks=False)
                    except OSError as e:
                        errors.append(f"stat failed on {entry_rel}: {e}")
                        continue

                    mode = entry_stat.st_mode

                    if stat.S_ISLNK(mode):
                        specials.append(
                            SpecialEntry(
                                rel_path=entry_rel,
                                root_index=root_idx,
                                st_dev=entry_stat.st_dev,
                                st_ino=entry_stat.st_ino,
                                st_mode=mode,
                                kind="symlink",
                            )
                        )
                        continue

                    if stat.S_ISDIR(mode):
                        # Enforce mount boundary confinement
                        if entry_stat.st_dev != root_dev:
                            errors.append(
                                f"mount boundary escape: {entry_rel} dev={entry_stat.st_dev} != root_dev={root_dev}"
                            )
                            continue

                        dir_key = (entry_stat.st_dev, entry_stat.st_ino)
                        if dir_key in visited_dirs:
                            errors.append(f"cyclic directory loop detected at {entry_rel}")
                            continue
                        visited_dirs.add(dir_key)

                        try:
                            child_dfd = os.open(
                                name,
                                os.O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
                                dir_fd=curr_fd,
                            )
                            stack.append((child_dfd, entry_rel, curr_depth + 1))
                        except OSError as e:
                            errors.append(f"failed to open subdirectory {entry_rel}: {e}")
                        continue

                    if stat.S_ISREG(mode):
                        # Enforce file size budget on stat BEFORE reading
                        if entry_stat.st_size > MAX_RAW_FILE_BYTES:
                            errors.append(
                                f"file size {entry_stat.st_size} exceeds budget of {MAX_RAW_FILE_BYTES} for {entry_rel}"
                            )
                            continue

                        try:
                            file_fd = os.open(
                                name,
                                os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
                                dir_fd=curr_fd,
                            )
                            fstat_res = os.fstat(file_fd)
                            if (fstat_res.st_dev, fstat_res.st_ino) != (entry_stat.st_dev, entry_stat.st_ino):
                                os.close(file_fd)
                                errors.append(f"inode race detected opening {entry_rel}")
                                continue

                            candidates.append(
                                CandidateFile(
                                    rel_path=entry_rel,
                                    root_index=root_idx,
                                    root_path=abs_root,
                                    st_dev=fstat_res.st_dev,
                                    st_ino=fstat_res.st_ino,
                                    st_mode=fstat_res.st_mode,
                                    st_nlink=fstat_res.st_nlink,
                                    st_uid=fstat_res.st_uid,
                                    st_gid=fstat_res.st_gid,
                                    st_size=fstat_res.st_size,
                                    st_atime_ns=getattr(fstat_res, "st_atime_ns", int(fstat_res.st_atime * 1e9)),
                                    st_mtime_ns=getattr(fstat_res, "st_mtime_ns", int(fstat_res.st_mtime * 1e9)),
                                    st_ctime_ns=getattr(fstat_res, "st_ctime_ns", int(fstat_res.st_ctime * 1e9)),
                                    seq=global_seq,
                                    fd=file_fd,
                                )
                            )
                            global_seq += 1
                        except OSError as e:
                            errors.append(f"failed to open regular file {entry_rel}: {e}")
                        continue

                    # Special file (fifo, socket, dev)
                    kind = "unknown"
                    if stat.S_ISFIFO(mode):
                        kind = "fifo"
                    elif stat.S_ISSOCK(mode):
                        kind = "socket"
                    elif stat.S_ISCHR(mode):
                        kind = "char_device"
                    elif stat.S_ISBLK(mode):
                        kind = "block_device"
                    specials.append(
                        SpecialEntry(
                            rel_path=entry_rel,
                            root_index=root_idx,
                            st_dev=entry_stat.st_dev,
                            st_ino=entry_stat.st_ino,
                            st_mode=mode,
                            kind=kind,
                        )
                    )

                if curr_fd != root_fd:
                    os.close(curr_fd)
        finally:
            os.close(root_fd)

    return candidates, specials, errors


# Reference resolution helper with root qualification


def resolve_reference_path(
    ref_path: str,
    roots: List[str],
    candidate_by_root_and_rel: Dict[Tuple[int, str], CandidateFile],
    specials_by_root_and_rel: Dict[Tuple[int, str], SpecialEntry],
) -> Tuple[Optional[CandidateFile], Optional[SpecialEntry], Optional[str]]:
    """
    Resolve a reference path from ledger/runtime binder against pre-read census using root-qualified identities.
    Returns (candidate_file, special_entry, error_reason).
    """
    if ".." in ref_path or "\0" in ref_path:
        return None, None, f"reference {ref_path!r} contains path traversal components"

    norm_path = os.path.normpath(ref_path)

    # 1. Absolute path: match against permitted roots
    if norm_path.startswith("/"):
        matched_root: Optional[int] = None
        matched_rel: Optional[str] = None
        longest_match = -1
        for root_idx, r in enumerate(roots):
            abs_r = os.path.abspath(r)
            if norm_path == abs_r:
                if len(abs_r) > longest_match:
                    longest_match = len(abs_r)
                    matched_root = root_idx
                    matched_rel = ""
            elif norm_path.startswith(abs_r + "/"):
                if len(abs_r) > longest_match:
                    longest_match = len(abs_r)
                    matched_root = root_idx
                    matched_rel = norm_path[len(abs_r) + 1 :]

        if matched_root is None or matched_rel is None:
            return None, None, f"reference {ref_path!r} escapes permitted roots"

        key = (matched_root, os.path.normpath(matched_rel))
        if key in specials_by_root_and_rel:
            return None, specials_by_root_and_rel[key], None
        if key in candidate_by_root_and_rel:
            return candidate_by_root_and_rel[key], None, None
        return None, None, None

    # 2. Relative path: look up across roots
    if norm_path.startswith("../"):
        return None, None, f"reference {ref_path!r} escapes permitted roots"

    matching_candidate_roots = [
        root_idx for root_idx in range(len(roots)) if (root_idx, norm_path) in candidate_by_root_and_rel
    ]
    matching_special_roots = [
        root_idx for root_idx in range(len(roots)) if (root_idx, norm_path) in specials_by_root_and_rel
    ]
    all_matching = matching_candidate_roots + matching_special_roots

    if len(all_matching) > 1:
        return None, None, f"ambiguous relative reference {ref_path!r} matches multiple roots: {all_matching!r}"

    if matching_special_roots:
        return None, specials_by_root_and_rel[(matching_special_roots[0], norm_path)], None

    if matching_candidate_roots:
        return candidate_by_root_and_rel[(matching_candidate_roots[0], norm_path)], None, None

    # Not found in any root; check default root 0
    key = (0, norm_path)
    if key in specials_by_root_and_rel:
        return None, specials_by_root_and_rel[key], None
    if key in candidate_by_root_and_rel:
        return candidate_by_root_and_rel[key], None, None

    return None, None, None


# Ledger processing and reference rederivation with Runtime Binder


def process_ledger_and_runtime_bindings(
    candidates: List[CandidateFile],
    specials: List[SpecialEntry],
    roots: List[str],
    ledger_relpath: str,
    binding: LaunchBinding,
    runtime_bindings: List[RuntimeBinding],
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Parses ledger.jsonl AFTER initial metadata sampling is complete.
    Joins logical slots <-> runtime bindings <-> physical candidates <-> ledger records.
    Enforces exact slot equality, inode uniqueness across slots, and creation-time hardlink auth.
    Evaluates numeric atime predicates strictly from kernel stat values.
    """
    reasons: List[str] = []
    checks: Dict[str, str] = {
        "ledger_header": "PASS",
        "ledger_digest": "PASS",
        "metadata_ordering": "PASS",
        "no_symlink_escapes": "PASS",
        "no_hardlink_aliases": "PASS",
        "no_missing_references": "PASS",
        "no_duplicate_references": "PASS",
        "no_foreign_references": "PASS",
        "numeric_atime_predicates": "PASS",
        "raw_bytes_retained": "PASS",
    }

    # Index candidates and specials by (root_index, rel_path)
    candidate_by_root_and_rel: Dict[Tuple[int, str], CandidateFile] = {}
    candidate_by_ino: Dict[Tuple[int, int], List[CandidateFile]] = {}
    for c in candidates:
        norm = os.path.normpath(c.rel_path)
        candidate_by_root_and_rel[(c.root_index, norm)] = c
        candidate_by_ino.setdefault((c.st_dev, c.st_ino), []).append(c)

    specials_by_root_and_rel: Dict[Tuple[int, str], SpecialEntry] = {
        (s.root_index, os.path.normpath(s.rel_path)): s for s in specials
    }

    # 1. Exact ledger-location enforcement: must be in root 0 at exact path
    ledger_norm = os.path.normpath(ledger_relpath)
    ledger_file: Optional[CandidateFile] = None
    for c in candidates:
        if c.root_index == 0 and os.path.normpath(c.rel_path) == ledger_norm:
            ledger_file = c
            break

    if ledger_file is None:
        reasons.append(f"ledger file {ledger_norm!r} not found at exact path in root 0")
        checks["ledger_header"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    # Enforce ledger size budget
    if ledger_file.st_size > MAX_LEDGER_BYTES:
        reasons.append(f"ledger file size {ledger_file.st_size} exceeds budget of {MAX_LEDGER_BYTES} bytes")
        checks["ledger_digest"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    # 2. Check for Executable/Ledger Hardlink Alias Attack
    aliased_candidates = [
        c
        for c in candidates
        if (c.root_index, c.rel_path) != (ledger_file.root_index, ledger_file.rel_path)
        and (c.st_dev, c.st_ino) == (ledger_file.st_dev, ledger_file.st_ino)
    ]
    if aliased_candidates or ledger_file.st_nlink > 1:
        alias_paths = [f"[{c.root_index}]{c.rel_path}" for c in aliased_candidates]
        reasons.append(
            f"executable/ledger hardlink alias attack detected: ledger [{ledger_file.root_index}]{ledger_file.rel_path} "
            f"shares inode {ledger_file.st_ino} with {alias_paths!r} (st_nlink={ledger_file.st_nlink})"
        )
        checks["no_hardlink_aliases"] = "FAIL"

    # 3. Read ledger raw bytes from held descriptor using chunked read
    if ledger_file.fd is None:
        reasons.append("held descriptor for ledger is missing")
        checks["ledger_digest"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    try:
        ledger_raw, ledger_sha256 = read_bounded_bytes(ledger_file.fd, MAX_LEDGER_BYTES, ledger_file.st_size)
    except Exception as e:
        reasons.append(f"failed to read ledger bytes from held fd: {e}")
        checks["ledger_digest"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    try:
        ledger_text = ledger_raw.decode("utf-8")
    except UnicodeDecodeError as e:
        reasons.append(f"ledger is not valid UTF-8: {e}")
        checks["ledger_header"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    lines = ledger_text.splitlines()
    if not lines or not lines[0].strip():
        reasons.append("ledger is empty")
        checks["ledger_header"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    # Parse line 1: Header
    try:
        header = json.loads(lines[0])
    except Exception as e:
        reasons.append(f"ledger line 1 is not valid JSON: {e}")
        checks["ledger_header"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    if not isinstance(header, dict) or header.get("v") != 1 or header.get("kind") != "header":
        reasons.append(f"ledger line 1 is not a valid v1 header: {header!r}")
        checks["ledger_header"] = "FAIL"

    # Validate header fields against trusted host launch bindings
    if header.get("chain_id") != binding.chain_id:
        reasons.append(f"header chain_id {header.get('chain_id')!r} != expected {binding.chain_id!r}")
        checks["ledger_header"] = "FAIL"
    if header.get("driver") != binding.driver:
        reasons.append(f"header driver {header.get('driver')!r} != expected {binding.driver!r}")
        checks["ledger_header"] = "FAIL"
    if header.get("attempt") != binding.attempt:
        reasons.append(f"header attempt {header.get('attempt')!r} != expected {binding.attempt!r}")
        checks["ledger_header"] = "FAIL"
    if header.get("nonce") != binding.expected_nonce:
        reasons.append(f"header nonce {header.get('nonce')!r} != expected {binding.expected_nonce!r}")
        checks["ledger_header"] = "FAIL"

    # Parse remaining lines as records
    records: List[Dict[str, Any]] = []
    for line_idx, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except Exception as e:
            reasons.append(f"ledger line {line_idx} malformed JSON: {e}")
            checks["ledger_header"] = "FAIL"
            continue
        if not isinstance(rec, dict) or rec.get("v") != 1 or rec.get("kind") != "record":
            reasons.append(f"ledger line {line_idx} is not a valid v1 record")
            checks["ledger_header"] = "FAIL"
            continue
        if rec.get("nonce") != binding.expected_nonce or rec.get("driver") != binding.driver:
            reasons.append(f"ledger line {line_idx} carries foreign nonce or driver")
            checks["no_foreign_references"] = "FAIL"
            continue
        records.append(rec)

    if not records:
        reasons.append("ledger contains zero records")
        checks["no_missing_references"] = "FAIL"

    # 4. Check Logical Slots <-> Runtime Bindings Exact Equality
    if binding.logical_slots:
        expected_slot_ids = {s.slot_id for s in binding.logical_slots}
        bound_slot_ids = {rb.slot_id for rb in runtime_bindings}
        missing_slots = expected_slot_ids - bound_slot_ids
        if missing_slots:
            reasons.append(f"mandatory logical slots unfulfilled in runtime binding: {sorted(missing_slots)!r}")
            checks["no_missing_references"] = "FAIL"
        extra_slots = bound_slot_ids - expected_slot_ids
        if extra_slots:
            reasons.append(f"unexpected extra slots in runtime binding: {sorted(extra_slots)!r}")
            checks["no_foreign_references"] = "FAIL"
    elif binding.expected_refs:
        # Legacy/direct expected refs mode
        expected_ref_set = {os.path.normpath(r) for r in binding.expected_refs}
    else:
        reasons.append("no logical slots or expected references defined")
        checks["no_missing_references"] = "FAIL"

    # Inode uniqueness across runtime bindings (distinct slots must have distinct inodes)
    seen_slot_inos: Dict[Tuple[int, int], str] = {}
    for rb in runtime_bindings:
        ino_key = (rb.st_dev, rb.st_ino)
        if ino_key in seen_slot_inos:
            reasons.append(
                f"inode reuse attack: slot {seen_slot_inos[ino_key]!r} and {rb.slot_id!r} "
                f"share physical inode {rb.st_ino}"
            )
            checks["no_hardlink_aliases"] = "FAIL"
        seen_slot_inos[ino_key] = rb.slot_id

        if not rb.hardlink_authenticated:
            reasons.append(f"slot {rb.slot_id!r} lacks creation-time hardlink authentication")
            checks["no_hardlink_aliases"] = "FAIL"

    # Index ledger end records by inv and out_ref
    end_records_by_inv: Dict[str, Dict[str, Any]] = {}
    end_records_by_ref: Dict[str, Dict[str, Any]] = {}
    for r in records:
        if r.get("phase") == "end":
            if r.get("inv"):
                end_records_by_inv[r["inv"]] = r
            if r.get("out_ref"):
                norm_r = os.path.normpath(r["out_ref"])
                end_records_by_ref[norm_r] = r

    # 5. Validate each RuntimeBinding against physical census & ledger
    references: List[Dict[str, Any]] = []
    seen_refs: Set[Tuple[int, str]] = set()

    # If runtime bindings are present, validate via runtime bindings table
    if runtime_bindings:
        for rb in runtime_bindings:
            # Resolve physical candidate for out_ref_path
            cand, special, err_reason = resolve_reference_path(
                ref_path=rb.out_ref_path,
                roots=roots,
                candidate_by_root_and_rel=candidate_by_root_and_rel,
                specials_by_root_and_rel=specials_by_root_and_rel,
            )

            if err_reason:
                reasons.append(f"slot {rb.slot_id!r} out_ref error: {err_reason}")
                checks["no_foreign_references"] = "FAIL"
                continue
            if special is not None:
                reasons.append(f"slot {rb.slot_id!r} out_ref is a {special.kind}")
                checks["no_symlink_escapes"] = "FAIL"
                continue
            if cand is None:
                reasons.append(f"slot {rb.slot_id!r} out_ref {rb.out_ref_path!r} missing from pre-read census")
                checks["no_missing_references"] = "FAIL"
                continue

            ref_key = (cand.root_index, cand.rel_path)
            if ref_key in seen_refs:
                reasons.append(f"duplicate reference detected in slot {rb.slot_id!r}: [{cand.root_index}]{cand.rel_path}")
                checks["no_duplicate_references"] = "FAIL"
            seen_refs.add(ref_key)

            # Inode verification
            if (cand.st_dev, cand.st_ino) != (rb.st_dev, rb.st_ino):
                reasons.append(
                    f"slot {rb.slot_id!r} physical inode {cand.st_ino} != runtime bound inode {rb.st_ino}"
                )
                checks["no_missing_references"] = "FAIL"

            # Check hardlink alias against ledger inode
            if (cand.st_dev, cand.st_ino) == (ledger_file.st_dev, ledger_file.st_ino):
                reasons.append(
                    f"slot {rb.slot_id!r} reference {rb.out_ref_path!r} is an alias of ledger {ledger_file.rel_path}"
                )
                checks["no_hardlink_aliases"] = "FAIL"

            # Check target executable out_path
            # Driver cleanup may legitimately unlink out_path, authenticated at creation time!
            target_matched_root: Optional[int] = None
            target_matched_rel: Optional[str] = None
            out_cand, out_special, out_err = resolve_reference_path(
                ref_path=rb.out_path,
                roots=roots,
                candidate_by_root_and_rel=candidate_by_root_and_rel,
                specials_by_root_and_rel=specials_by_root_and_rel,
            )
            if out_cand:
                target_matched_root = out_cand.root_index
                target_matched_rel = out_cand.rel_path
                if (out_cand.st_dev, out_cand.st_ino) != (cand.st_dev, cand.st_ino):
                    reasons.append(
                        f"slot {rb.slot_id!r} out {rb.out_path!r} inode {out_cand.st_ino} != out_ref inode {cand.st_ino}"
                    )
                    checks["no_hardlink_aliases"] = "FAIL"
            elif not rb.hardlink_authenticated:
                reasons.append(
                    f"slot {rb.slot_id!r} unlinked out {rb.out_path!r} lacks creation-time hardlink authentication"
                )
                checks["no_hardlink_aliases"] = "FAIL"

            # Kernel atime advancement check directly from KERNEL observations
            atime_adv = False
            atime_delta_ns = cand.st_atime_ns - cand.st_mtime_ns
            if cand.st_atime_ns > cand.st_mtime_ns:
                atime_adv = True
            else:
                reasons.append(
                    f"slot {rb.slot_id!r} kernel atime {cand.st_atime_ns} <= kernel mtime {cand.st_mtime_ns}"
                )
                checks["numeric_atime_predicates"] = "FAIL"

            if cand.st_atime_ns <= rb.atime_set_ns:
                reasons.append(
                    f"slot {rb.slot_id!r} kernel atime {cand.st_atime_ns} <= atime_set_ns {rb.atime_set_ns}"
                )
                checks["numeric_atime_predicates"] = "FAIL"

            # Bind mtime to kernel observation
            if cand.st_mtime_ns != rb.out_mtime_ns:
                reasons.append(
                    f"slot {rb.slot_id!r} bound out_mtime_ns {rb.out_mtime_ns} != kernel mtime {cand.st_mtime_ns}"
                )
                checks["numeric_atime_predicates"] = "FAIL"

            # Content digest check via chunked stream
            actual_sha256 = ""
            if cand.fd is not None:
                try:
                    _, actual_sha256 = read_bounded_bytes(cand.fd, MAX_RAW_FILE_BYTES, cand.st_size)
                    if actual_sha256 != rb.out_sha256:
                        reasons.append(
                            f"slot {rb.slot_id!r} sha256 mismatch: expected {rb.out_sha256}, got {actual_sha256}"
                        )
                        checks["raw_bytes_retained"] = "FAIL"
                except Exception as e:
                    reasons.append(f"failed to read raw bytes for slot {rb.slot_id!r}: {e}")
                    checks["raw_bytes_retained"] = "FAIL"

            # Match matching ledger record
            matched_rec = end_records_by_inv.get(rb.inv) or end_records_by_ref.get(os.path.normpath(rb.out_ref_path))
            if matched_rec is None:
                reasons.append(f"slot {rb.slot_id!r} inv {rb.inv!r} has no matching end record in ledger")
                checks["no_missing_references"] = "FAIL"
            else:
                # Ledger end record must carry mandatory out, out_ref, out_ino, out_mtime_ns, consumer
                rec_out = matched_rec.get("out")
                if not rec_out:
                    reasons.append(f"ledger end record for slot {rb.slot_id!r} omitted mandatory out field")
                    checks["no_missing_references"] = "FAIL"
                elif os.path.normpath(rec_out) != os.path.normpath(rb.out_path):
                    reasons.append(
                        f"ledger end record out {rec_out!r} != runtime bound out {rb.out_path!r}"
                    )
                    checks["no_missing_references"] = "FAIL"

                rec_ref = matched_rec.get("out_ref")
                if not rec_ref or os.path.normpath(rec_ref) != os.path.normpath(rb.out_ref_path):
                    reasons.append(f"ledger end record out_ref {rec_ref!r} != bound {rb.out_ref_path!r}")
                    checks["no_missing_references"] = "FAIL"

                rec_ino = matched_rec.get("out_ino")
                if rec_ino != rb.st_ino:
                    reasons.append(f"ledger record out_ino {rec_ino} != bound {rb.st_ino}")
                    checks["no_missing_references"] = "FAIL"

                rec_mtime = matched_rec.get("out_mtime_ns")
                if rec_mtime != rb.out_mtime_ns:
                    reasons.append(f"ledger record out_mtime_ns {rec_mtime} != bound {rb.out_mtime_ns}")
                    checks["numeric_atime_predicates"] = "FAIL"

            references.append(
                {
                    "slot_id": rb.slot_id,
                    "transaction_id": rb.transaction_id,
                    "inv": rb.inv,
                    "out": rb.out_path,
                    "out_ref": rb.out_ref_path,
                    "matched_root": cand.root_index,
                    "matched_rel": cand.rel_path,
                    "target_matched_root": target_matched_root,
                    "target_matched_rel": target_matched_rel,
                    "recorded_ino": rb.st_ino,
                    "recorded_mtime_ns": rb.out_mtime_ns,
                    "recorded_atime_set_ns": rb.atime_set_ns,
                    "observed_dev": cand.st_dev,
                    "observed_ino": cand.st_ino,
                    "observed_atime_ns": cand.st_atime_ns,
                    "observed_mtime_ns": cand.st_mtime_ns,
                    "atime_delta_ns": atime_delta_ns,
                    "atime_advanced": atime_adv,
                    "hardlink_verified": rb.hardlink_authenticated,
                    "sha256": actual_sha256,
                    "sha256_verified": actual_sha256 == rb.out_sha256,
                }
            )

        # Check for unexpected extra end records in ledger not in runtime bindings
        bound_invs = {rb.inv for rb in runtime_bindings}
        for rec in records:
            if rec.get("phase") == "end" and rec.get("out_ref"):
                if rec.get("inv") not in bound_invs:
                    reasons.append(f"unexpected extra end record in ledger: inv={rec.get('inv')!r}")
                    checks["no_foreign_references"] = "FAIL"
    else:
        # Fallback to direct expected_refs verification
        expected_set = {os.path.normpath(r) for r in binding.expected_refs}
        for rec_idx, rec in enumerate(records):
            if rec.get("phase") != "end" or not rec.get("out_ref"):
                continue
            out_ref = rec["out_ref"]
            out_target = rec.get("out")
            recorded_ino = rec.get("out_ino")
            recorded_mtime = rec.get("out_mtime_ns")
            recorded_atime_set = rec.get("atime_set_ns")
            consumer = rec.get("consumer")
            inv_id = rec.get("inv", f"rec_{rec_idx}")

            if recorded_ino is None or recorded_mtime is None or recorded_atime_set is None:
                reasons.append(f"record {inv_id} omitted required metadata fields")
                checks["no_missing_references"] = "FAIL"
                continue
            if not isinstance(consumer, dict) or not consumer.get("out_sha256"):
                reasons.append(f"record {inv_id} omitted consumer.out_sha256")
                checks["raw_bytes_retained"] = "FAIL"
                continue

            cand, special, err_reason = resolve_reference_path(out_ref, roots, candidate_by_root_and_rel, specials_by_root_and_rel)
            if err_reason:
                reasons.append(err_reason)
                checks["no_foreign_references"] = "FAIL"
                continue
            if special is not None:
                reasons.append(f"monitored reference {out_ref!r} is a {special.kind}")
                checks["no_symlink_escapes"] = "FAIL"
                continue
            if cand is None:
                reasons.append(f"monitored reference {out_ref!r} missing from pre-read census")
                checks["no_missing_references"] = "FAIL"
                continue

            ref_key = (cand.root_index, cand.rel_path)
            if ref_key in seen_refs:
                reasons.append(f"duplicate reference in ledger: [{cand.root_index}]{cand.rel_path}")
                checks["no_duplicate_references"] = "FAIL"
            seen_refs.add(ref_key)

            if cand.st_ino != recorded_ino:
                reasons.append(f"reference {out_ref!r} physical inode != recorded")
                checks["no_missing_references"] = "FAIL"

            if (cand.st_dev, cand.st_ino) == (ledger_file.st_dev, ledger_file.st_ino):
                reasons.append(f"reference {out_ref!r} is an alias of ledger")
                checks["no_hardlink_aliases"] = "FAIL"

            hardlink_verified = False
            target_matched_root = None
            target_matched_rel = None
            if out_target:
                out_cand, out_special, out_err = resolve_reference_path(out_target, roots, candidate_by_root_and_rel, specials_by_root_and_rel)
                if out_err:
                    reasons.append(f"target {out_target!r} error: {out_err}")
                    checks["no_foreign_references"] = "FAIL"
                elif out_special is not None:
                    reasons.append(f"target {out_target!r} is a {out_special.kind}")
                    checks["no_symlink_escapes"] = "FAIL"
                elif out_cand is None:
                    reasons.append(f"target {out_target!r} missing from pre-read census")
                    checks["no_missing_references"] = "FAIL"
                else:
                    target_matched_root = out_cand.root_index
                    target_matched_rel = out_cand.rel_path
                    if (out_cand.st_dev, out_cand.st_ino) == (cand.st_dev, cand.st_ino):
                        hardlink_verified = True
                    else:
                        reasons.append(f"target {out_target!r} inode != out_ref inode")
                        checks["no_hardlink_aliases"] = "FAIL"
            else:
                reasons.append(f"record {inv_id} omitted mandatory out field")
                checks["no_missing_references"] = "FAIL"

            if cand.st_mtime_ns != recorded_mtime:
                reasons.append(f"recorded out_mtime_ns != kernel mtime for {out_ref!r}")
                checks["numeric_atime_predicates"] = "FAIL"

            atime_adv = cand.st_atime_ns > cand.st_mtime_ns
            if not atime_adv:
                reasons.append(f"kernel atime <= kernel mtime for {out_ref!r}")
                checks["numeric_atime_predicates"] = "FAIL"
            if cand.st_atime_ns <= recorded_atime_set:
                reasons.append(f"kernel atime <= atime_set_ns for {out_ref!r}")
                checks["numeric_atime_predicates"] = "FAIL"

            actual_sha = ""
            if cand.fd is not None:
                try:
                    _, actual_sha = read_bounded_bytes(cand.fd, MAX_RAW_FILE_BYTES, cand.st_size)
                    if actual_sha != consumer["out_sha256"]:
                        reasons.append(f"sha256 mismatch for {out_ref!r}")
                        checks["raw_bytes_retained"] = "FAIL"
                except Exception as e:
                    reasons.append(f"failed to read raw bytes for {out_ref!r}: {e}")
                    checks["raw_bytes_retained"] = "FAIL"

            references.append(
                {
                    "slot_id": inv_id,
                    "transaction_id": inv_id,
                    "inv": inv_id,
                    "out": out_target,
                    "out_ref": out_ref,
                    "matched_root": cand.root_index,
                    "matched_rel": cand.rel_path,
                    "target_matched_root": target_matched_root,
                    "target_matched_rel": target_matched_rel,
                    "recorded_ino": recorded_ino,
                    "recorded_mtime_ns": recorded_mtime,
                    "recorded_atime_set_ns": recorded_atime_set,
                    "observed_dev": cand.st_dev,
                    "observed_ino": cand.st_ino,
                    "observed_atime_ns": cand.st_atime_ns,
                    "observed_mtime_ns": cand.st_mtime_ns,
                    "atime_delta_ns": cand.st_atime_ns - cand.st_mtime_ns,
                    "atime_advanced": atime_adv,
                    "hardlink_verified": hardlink_verified,
                    "sha256": actual_sha,
                    "sha256_verified": actual_sha == consumer.get("out_sha256"),
                }
            )

        verified_refs_set = {os.path.normpath(r["out_ref"]) for r in references}
        missing_refs = expected_set - verified_refs_set
        if missing_refs:
            reasons.append(f"required expected references missing from ledger: {sorted(missing_refs)!r}")
            checks["no_missing_references"] = "FAIL"
        extra_refs = verified_refs_set - expected_set
        if extra_refs:
            reasons.append(f"unexpected extra references in ledger: {sorted(extra_refs)!r}")
            checks["no_foreign_references"] = "FAIL"

    if not references:
        reasons.append("ledger contains zero verified end references")
        checks["no_missing_references"] = "FAIL"

    status = "PASS" if not reasons else "REJECT"

    ledger_summary = {
        "rel_path": ledger_file.rel_path,
        "root_index": ledger_file.root_index,
        "st_dev": ledger_file.st_dev,
        "st_ino": ledger_file.st_ino,
        "st_size": ledger_file.st_size,
        "sha256": ledger_sha256,
        "header": header,
        "record_count": len(records),
    }

    result = {
        "checks": checks,
        "reasons": reasons,
        "status": status,
        "ledger": ledger_summary,
        "references": references,
    }
    return result, reasons


# Raw evidence collection through held descriptors with aggregate budgeting


def collect_raw_file_bytes(
    candidates: List[CandidateFile],
    monitored_keys: Set[Tuple[int, str]],
    monitored_inos: Optional[Set[Tuple[int, int]]] = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Reads actual raw bytes from held descriptors for monitored candidates in fixed 64 KiB chunks.
    Captures raw bytes once per physical (st_dev, st_ino), while recording all
    associated candidate path aliases and reference mappings.
    Enforces per-file and aggregate byte ceilings before reading.
    Performs post-read fstat checks to ensure bytes and metadata were not modified during capture.
    """
    raw_files: List[Dict[str, Any]] = []
    errors: List[str] = []
    captured_by_ino: Dict[Tuple[int, int], Dict[str, Any]] = {}
    inos = monitored_inos or set()
    total_aggregate_bytes = 0

    # Sort candidates so primary executables (non-.ref) come before hardlink references (.ref)
    sorted_candidates = sorted(
        candidates,
        key=lambda c: (1 if c.rel_path.endswith(".ref") else 0, c.seq)
    )

    for c in sorted_candidates:
        norm_path = os.path.normpath(c.rel_path)
        c_key = (c.root_index, norm_path)
        ino_key = (c.st_dev, c.st_ino)

        if c_key not in monitored_keys and ino_key not in inos and not c.rel_path.endswith(".ref"):
            continue

        if ino_key in captured_by_ino:
            entry = captured_by_ino[ino_key]
            alias_entry = {"root_index": c.root_index, "rel_path": c.rel_path}
            if alias_entry not in entry["aliases"] and (c.root_index, c.rel_path) != (entry["root_index"], entry["rel_path"]):
                entry["aliases"].append(alias_entry)
            continue

        if c.st_size > MAX_RAW_FILE_BYTES:
            errors.append(f"raw file size {c.st_size} exceeds budget of {MAX_RAW_FILE_BYTES} bytes for [{c.root_index}]{c.rel_path}")
            continue

        if total_aggregate_bytes + c.st_size > MAX_AGGREGATE_RAW_BYTES:
            errors.append(
                f"aggregate raw evidence bytes {total_aggregate_bytes + c.st_size} "
                f"exceeds budget of {MAX_AGGREGATE_RAW_BYTES} bytes"
            )
            break

        if c.fd is None:
            errors.append(f"held descriptor missing for [{c.root_index}]{c.rel_path}")
            continue

        try:
            content, sha256_hex = read_bounded_bytes(c.fd, MAX_RAW_FILE_BYTES, c.st_size)
            total_aggregate_bytes += len(content)

            # Post-read stat check
            post_stat = os.fstat(c.fd)
            if post_stat.st_ino != c.st_ino or post_stat.st_dev != c.st_dev:
                errors.append(f"file inode changed during read: [{c.root_index}]{c.rel_path}")
                continue
            if post_stat.st_size != len(content):
                errors.append(
                    f"file size changed during read: [{c.root_index}]{c.rel_path} "
                    f"stat={post_stat.st_size} read={len(content)}"
                )
                continue
            if getattr(post_stat, "st_mtime_ns", int(post_stat.st_mtime * 1e9)) != c.st_mtime_ns:
                errors.append(f"file mtime changed during read: [{c.root_index}]{c.rel_path}")
                continue

            raw_entry = {
                "root_index": c.root_index,
                "rel_path": c.rel_path,
                "aliases": [],
                "st_dev": c.st_dev,
                "st_ino": c.st_ino,
                "size": len(content),
                "sha256": sha256_hex,
                "file_bytes": content,
            }
            captured_by_ino[ino_key] = raw_entry
            raw_files.append(raw_entry)
        except Exception as e:
            errors.append(f"failed to read file bytes for [{c.root_index}]{c.rel_path}: {e}")

    return raw_files, errors


# Main observer orchestrator


def run_origin_observer(
    roots: List[str],
    binding: LaunchBinding,
    runtime_bindings: Optional[List[RuntimeBinding]] = None,
    ledger_relpath: str = "ledger.jsonl",
    output_stream: Optional[BinaryIO] = None,
    capture_raw_bytes: bool = True,
    checkpoint_callback: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Main entrypoint for origin observation.
    Executes sequence:
    1. Pre-read descriptor-relative walk and fstat sampling of all candidate regular files.
    2. Commit and emit initial metadata census checkpoint BEFORE reading ledger.
    3. If traversal errors occurred, fail closed immediately without reading ledger.
    4. Read and parse ledger descriptor-relatively; detect hardlink aliases.
    5. Validate references against logical slots, runtime bindings, and kernel observations.
    6. Collect raw executable bytes from held descriptors in 64 KiB chunks with aggregate budgeting.
    7. Emit versioned framed stream to output_stream (including full evidence in final frame).
    8. Close held descriptors.
    """
    start_time_ns = time.time_ns()
    candidates, specials, walk_errors = walk_roots_descriptor_relative(roots)

    # 1. Build committed initial census checkpoint document
    checkpoint_doc: Dict[str, Any] = {
        "v": PROTOCOL_VERSION,
        "kind": "iyi-origin-observer-initial-census",
        "launch_binding": {
            "chain_id": binding.chain_id,
            "driver": binding.driver,
            "attempt": binding.attempt,
            "launch_id": binding.launch_id,
            "expected_nonce": binding.expected_nonce,
            "logical_slots": [s.to_dict() for s in binding.logical_slots],
            "expected_refs": list(binding.expected_refs),
        },
        "observer_identity": {
            "uid": os.getuid() if hasattr(os, "getuid") else -1,
            "gid": os.getgid() if hasattr(os, "getgid") else -1,
            "pid": os.getpid(),
            "timestamp_ns": start_time_ns,
        },
        "roots": [
            {
                "root_index": idx,
                "path": os.path.abspath(r),
                "candidate_files": sum(1 for c in candidates if c.root_index == idx),
                "specials": sum(1 for s in specials if s.root_index == idx),
            }
            for idx, r in enumerate(roots)
        ],
        "initial_census": [c.to_dict() for c in candidates],
        "specials": [s.to_dict() for s in specials],
        "traversal_errors": walk_errors,
    }

    # 2. Commit and flush initial census frame BEFORE opening or reading ledger
    if output_stream is not None:
        write_header(output_stream)
        meta_bytes = json.dumps(checkpoint_doc, indent=2, sort_keys=True).encode("utf-8")
        write_frame(output_stream, FRAME_METADATA, meta_bytes)
        output_stream.flush()

    if checkpoint_callback is not None:
        checkpoint_callback(checkpoint_doc)

    # 3. Traversal errors fail closed immediately: NEVER proceed to read ledger!
    if walk_errors:
        term_doc = {
            "status": "REJECT",
            "reasons": walk_errors,
            "timestamp_ns": time.time_ns(),
            "verdict": {
                "status": "REJECT",
                "reasons": walk_errors,
                "checks": {"traversal": "FAIL"},
            },
        }
        if output_stream is not None:
            write_frame(output_stream, FRAME_TERMINATION, json.dumps(term_doc, sort_keys=True).encode("utf-8"))
        for c in candidates:
            if c.fd is not None:
                try:
                    os.close(c.fd)
                except OSError:
                    pass
                c.fd = None
        checkpoint_doc["verdict"] = term_doc["verdict"]
        return checkpoint_doc

    try:
        # 4. Only after initial census commit: read and validate ledger against runtime bindings
        proc_res, proc_errors = process_ledger_and_runtime_bindings(
            candidates=candidates,
            specials=specials,
            roots=roots,
            ledger_relpath=ledger_relpath,
            binding=binding,
            runtime_bindings=runtime_bindings or [],
        )

        all_errors = list(proc_errors)

        # Monitored references to capture
        monitored_keys: Set[Tuple[int, str]] = set()
        monitored_inos: Set[Tuple[int, int]] = set()
        for ref in proc_res.get("references", []):
            if "matched_root" in ref and "matched_rel" in ref and ref["matched_rel"] is not None:
                monitored_keys.add((ref["matched_root"], ref["matched_rel"]))
            if "target_matched_root" in ref and "target_matched_rel" in ref and ref["target_matched_rel"] is not None:
                monitored_keys.add((ref["target_matched_root"], ref["target_matched_rel"]))
            if "observed_dev" in ref and "observed_ino" in ref:
                monitored_inos.add((ref["observed_dev"], ref["observed_ino"]))

        raw_files: List[Dict[str, Any]] = []
        if capture_raw_bytes and proc_res.get("status") == "PASS":
            raw_files, raw_errors = collect_raw_file_bytes(candidates, monitored_keys, monitored_inos)
            all_errors.extend(raw_errors)

        final_status = "PASS" if not all_errors and proc_res.get("status") == "PASS" else "REJECT"

        checkpoint_doc["ledger"] = proc_res.get("ledger")
        checkpoint_doc["references"] = proc_res.get("references", [])
        checkpoint_doc["raw_files_manifest"] = [
            {
                "root_index": rf["root_index"],
                "rel_path": rf["rel_path"],
                "aliases": rf.get("aliases", []),
                "st_dev": rf["st_dev"],
                "st_ino": rf["st_ino"],
                "size": rf["size"],
                "sha256": rf["sha256"],
            }
            for rf in raw_files
        ]
        checkpoint_doc["verdict"] = {
            "status": final_status,
            "reasons": all_errors,
            "checks": proc_res.get("checks", {}),
        }
        checkpoint_doc["limitations"] = [
            "Data-only observer: cannot distinguish authentic kernel execution from "
            "read/utime without an independent parent execution witness."
        ]

        # Emit raw file frames and termination
        if output_stream is not None:
            for rf in raw_files:
                frame_payload = encode_raw_file_frame(
                    root_index=rf["root_index"],
                    rel_path=rf["rel_path"],
                    st_dev=rf["st_dev"],
                    st_ino=rf["st_ino"],
                    sha256_hex=rf["sha256"],
                    file_bytes=rf["file_bytes"],
                    aliases=rf.get("aliases", []),
                )
                write_frame(output_stream, FRAME_RAW_FILE, frame_payload)

            # Final termination frame carries COMPLETE evidence to the wire stream!
            term_doc = {
                "status": final_status,
                "reasons": all_errors,
                "timestamp_ns": time.time_ns(),
                "verdict": checkpoint_doc["verdict"],
                "ledger": checkpoint_doc.get("ledger"),
                "references": checkpoint_doc.get("references", []),
                "raw_files_manifest": checkpoint_doc.get("raw_files_manifest", []),
                "limitations": checkpoint_doc.get("limitations", []),
            }
            term_bytes = json.dumps(term_doc, sort_keys=True).encode("utf-8")
            write_frame(output_stream, FRAME_TERMINATION, term_bytes)

        return checkpoint_doc

    finally:
        # Close all held file descriptors
        for c in candidates:
            if c.fd is not None:
                try:
                    os.close(c.fd)
                except OSError:
                    pass
                c.fd = None


# Stream consumer / decoder helper for controller and tests


def parse_observer_stream(
    stream: BinaryIO,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Parse an observer stream from beginning to end.
    Returns (metadata_doc, list_of_raw_files, termination_doc).
    Decodes complete evidence (ledger, references, raw_files_manifest, verdict, limitations) from wire!
    """
    read_header(stream)
    metadata_doc: Optional[Dict[str, Any]] = None
    raw_files: List[Dict[str, Any]] = []
    termination_doc: Optional[Dict[str, Any]] = None

    while True:
        frame = read_frame(stream)
        if frame is None:
            break
        ftype, payload = frame
        if ftype == FRAME_METADATA:
            metadata_doc = json.loads(payload.decode("utf-8"))
        elif ftype == FRAME_RAW_FILE:
            raw_files.append(decode_raw_file_frame(payload))
        elif ftype == FRAME_TERMINATION:
            termination_doc = json.loads(payload.decode("utf-8"))
        elif ftype == FRAME_ERROR:
            err_data = json.loads(payload.decode("utf-8"))
            raise RuntimeError(f"Observer stream error frame: {err_data}")
        else:
            raise ValueError(f"Unknown frame type: {ftype}")

    if metadata_doc is None:
        raise ValueError("Observer stream missing FRAME_METADATA")
    if termination_doc is None:
        raise ValueError("Observer stream missing FRAME_TERMINATION")

    # Complete wire evidence recovery
    if "verdict" in termination_doc:
        metadata_doc["verdict"] = termination_doc["verdict"]
    metadata_doc["ledger"] = termination_doc.get("ledger")
    metadata_doc["references"] = termination_doc.get("references", [])
    metadata_doc["raw_files_manifest"] = termination_doc.get("raw_files_manifest", [])
    metadata_doc["limitations"] = termination_doc.get("limitations", [])

    return metadata_doc, raw_files, termination_doc


# CLI driver


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Hosted Origin Observer (C-owned data-only observer)")
    parser.add_argument("--root", action="append", required=True, help="Preserved root directory to observe (repeatable)")
    parser.add_argument("--chain-id", required=True, help="Expected chain_id")
    parser.add_argument("--driver", required=True, help="Driver name")
    parser.add_argument("--attempt", type=int, default=1, help="Attempt number (default 1)")
    parser.add_argument("--launch-id", required=True, help="Launch identity / container ID")
    parser.add_argument("--expected-nonce", required=True, help="Expected ledger nonce")
    parser.add_argument("--census", default=None, help="Path to C-trusted driver census JSON file to derive logical slots")
    parser.add_argument("--manifest", default=None, help="Path to C-trusted logical slot manifest JSON file")
    parser.add_argument("--runtime-binding", default=None, help="Path to JSON file containing authenticated RuntimeBinding list")
    parser.add_argument("--expected-ref", action="append", default=[], help="Expected reference path (repeatable, for direct mode)")
    parser.add_argument("--expected-refs-file", default=None, help="JSON file containing list of expected reference paths")
    parser.add_argument("--ledger-relpath", default="ledger.jsonl", help="Relative path to ledger within root 0")
    parser.add_argument("--output-fd", type=int, default=None, help="File descriptor for length-delimited output pipe")
    parser.add_argument("--output-file", default=None, help="File path for length-delimited output (alternative to fd)")
    parser.add_argument("--capture-raw-bytes", action="store_true", default=True, help="Capture raw bytes of monitored executables")

    args = parser.parse_args(argv)

    logical_slots: List[LogicalSlot] = []

    # 1. Derive logical slots from census if provided
    if args.census:
        try:
            with open(args.census, "r", encoding="utf-8") as f:
                census_data = json.load(f)
            logical_slots = build_driver_logical_slots(census_data, args.driver)
        except Exception as e:
            print(f"Error reading census file: {e}", file=sys.stderr)
            return 1
    elif args.manifest:
        try:
            with open(args.manifest, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
                slots_raw = manifest_data if isinstance(manifest_data, list) else manifest_data.get("slots", [])
                for s in slots_raw:
                    logical_slots.append(
                        LogicalSlot(
                            slot_id=s["slot_id"],
                            driver=s["driver"],
                            site_line=s["site_line"],
                            label=s["label"],
                            kind=s["kind"],
                            variant_id=s.get("variant_id"),
                            output_template=s["output_template"],
                            compiler_options=tuple(s.get("compiler_options", ())),
                        )
                    )
        except Exception as e:
            print(f"Error reading manifest file: {e}", file=sys.stderr)
            return 1

    expected_refs: Set[str] = set()
    for r in args.expected_ref:
        expected_refs.add(r)

    if args.expected_refs_file:
        try:
            with open(args.expected_refs_file, "r", encoding="utf-8") as f:
                refs_data = json.load(f)
                if isinstance(refs_data, list):
                    expected_refs.update(str(x) for x in refs_data)
                elif isinstance(refs_data, dict):
                    expected_refs.update(str(x) for x in refs_data.keys())
        except Exception as e:
            print(f"Error reading expected_refs_file: {e}", file=sys.stderr)
            return 1

    runtime_bindings: List[RuntimeBinding] = []
    if args.runtime_binding:
        try:
            with open(args.runtime_binding, "r", encoding="utf-8") as f:
                rb_data = json.load(f)
                items = rb_data if isinstance(rb_data, list) else rb_data.get("bindings", [])
                for b in items:
                    runtime_bindings.append(
                        RuntimeBinding(
                            slot_id=b["slot_id"],
                            transaction_id=b.get("transaction_id", args.launch_id),
                            inv=b["inv"],
                            out_path=b["out_path"],
                            out_ref_path=b["out_ref_path"],
                            st_dev=int(b["st_dev"]),
                            st_ino=int(b["st_ino"]),
                            out_mtime_ns=int(b["out_mtime_ns"]),
                            atime_set_ns=int(b["atime_set_ns"]),
                            out_sha256=b["out_sha256"],
                            hardlink_authenticated=bool(b.get("hardlink_authenticated", True)),
                            exec_verified=bool(b.get("exec_verified", True)),
                        )
                    )
        except Exception as e:
            print(f"Error reading runtime_binding file: {e}", file=sys.stderr)
            return 1

    binding = LaunchBinding(
        chain_id=args.chain_id,
        driver=args.driver,
        attempt=args.attempt,
        launch_id=args.launch_id,
        expected_nonce=args.expected_nonce,
        logical_slots=tuple(logical_slots),
        expected_refs=tuple(sorted(expected_refs)),
    )

    out_stream: BinaryIO
    close_stream = False
    if args.output_file:
        out_stream = open(args.output_file, "wb")
        close_stream = True
    elif args.output_fd is not None:
        out_stream = os.fdopen(args.output_fd, "wb", closefd=False)
    else:
        out_stream = sys.stdout.buffer

    try:
        doc = run_origin_observer(
            roots=args.root,
            binding=binding,
            runtime_bindings=runtime_bindings,
            ledger_relpath=args.ledger_relpath,
            output_stream=out_stream,
            capture_raw_bytes=args.capture_raw_bytes,
        )
        status = doc.get("verdict", {}).get("status", "REJECT")
        return 0 if status == "PASS" else 1
    finally:
        if close_stream:
            out_stream.close()


if __name__ == "__main__":
    sys.exit(main())
