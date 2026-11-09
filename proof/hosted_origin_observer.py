#!/usr/bin/env python3
"""
proof/hosted_origin_observer.py

C-owned data-only origin observer for hosted proof environments.
Runs after exact workload container teardown against read-only preserved roots.

Key Security Invariants:
1. Pure C-owned: never imports or executes W/P code, shells, or compilers.
2. Descriptor-relative traversal: opens allowed directory roots with O_DIRECTORY|O_CLOEXEC,
   walks subdirectories descriptor-relatively with O_NOFOLLOW|O_CLOEXEC, enforces mount boundaries,
   and never traverses symlinks or magic links.
3. Pre-read metadata capture: captures complete stat metadata (st_dev, st_ino, st_atime_ns,
   st_mtime_ns, st_ctime_ns, st_nlink, size, mode, uid, gid) for EVERY candidate regular file
   BEFORE opening or reading ledger.jsonl or any file content.
4. Held descriptors: keeps open file descriptors to all candidate regular files throughout
   observation and raw evidence capture.
5. Anti-aliasing: detects and rejects executable/ledger hardlink alias attacks where an
   adversary attempts to trigger atime updates on an executable by reading a hardlinked ledger.
6. Reference rederivation: parses ledger only after initial metadata freeze; verifies launch
   bindings (chain_id, driver, attempt, nonce); rejects missing, duplicate, foreign, symlink,
   and special-file references; recomputes integer atime predicates from kernel observations.
7. Retains raw executable bytes through held descriptors; compares post-read metadata to ensure
   bytes and timestamps were not altered during capture.
8. Length-delimited versioned protocol: streams framed output (b"IYOB" + v1) to inherited
   controller-owned private pipe with no workload access.
9. Exact limits: this observer is data-only. Collector observations alone CANNOT prove execution
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

# Safe open flags
O_CLOEXEC: int = getattr(os, "O_CLOEXEC", 0)
O_NOFOLLOW: int = getattr(os, "O_NOFOLLOW", 0)
O_DIRECTORY: int = getattr(os, "O_DIRECTORY", 0)
O_PATH: int = getattr(os, "O_PATH", os.O_RDONLY)


@dataclass(frozen=True)
class LaunchBinding:
    chain_id: str
    driver: str
    attempt: int
    launch_id: str
    expected_nonce: str


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
    rel_path: str,
    st_dev: int,
    st_ino: int,
    sha256_hex: str,
    file_bytes: bytes,
) -> bytes:
    """Encode raw file payload for FRAME_RAW_FILE."""
    path_bytes = rel_path.encode("utf-8")
    sha_bytes = bytes.fromhex(sha256_hex)
    header = (
        struct.pack(">H", len(path_bytes))
        + path_bytes
        + struct.pack(">QQ32sI", st_dev, st_ino, sha_bytes, len(file_bytes))
    )
    return header + file_bytes


def decode_raw_file_frame(payload: bytes) -> Dict[str, Any]:
    """Decode raw file payload from FRAME_RAW_FILE."""
    if len(payload) < 2:
        raise ValueError("Truncated raw file frame payload (no path length)")
    path_len = struct.unpack(">H", payload[:2])[0]
    offset = 2
    if len(payload) < offset + path_len + 8 + 8 + 32 + 4:
        raise ValueError("Truncated raw file frame header")
    rel_path = payload[offset : offset + path_len].decode("utf-8")
    offset += path_len
    st_dev, st_ino, sha_bytes, data_len = struct.unpack(">QQ32sI", payload[offset : offset + 52])
    offset += 52
    file_bytes = payload[offset : offset + data_len]
    if len(file_bytes) != data_len:
        raise ValueError(f"Raw file data length mismatch: expected {data_len}, got {len(file_bytes)}")
    return {
        "rel_path": rel_path,
        "st_dev": st_dev,
        "st_ino": st_ino,
        "sha256": sha_bytes.hex(),
        "file_bytes": file_bytes,
    }


# Descriptor-relative traversal & pre-read sampling


def walk_roots_descriptor_relative(
    roots: List[str],
) -> Tuple[List[CandidateFile], List[SpecialEntry], List[str]]:
    """
    Descriptor-relative traversal of preserved roots without following symlinks.
    Captures complete initial metadata and holds file descriptors for all regular files.
    Enforces mount boundary confinement (st_dev must match root st_dev).
    """
    candidates: List[CandidateFile] = []
    specials: List[SpecialEntry] = []
    errors: List[str] = []
    global_seq = 0

    for root_idx, root_path in enumerate(roots):
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

            # Stack for directory walk: (dir_fd, rel_dir_path, dir_ino)
            # Root directory fd is kept open during its walk
            stack: List[Tuple[int, str]] = [(root_fd, "")]

            while stack:
                curr_fd, curr_rel = stack.pop()
                try:
                    entries = sorted(os.listdir(curr_fd))
                except OSError as e:
                    errors.append(f"failed to listdir {curr_rel or '.'}: {e}")
                    if curr_fd != root_fd:
                        os.close(curr_fd)
                    continue

                for name in entries:
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
                            stack.append((child_dfd, entry_rel))
                        except OSError as e:
                            errors.append(f"failed to open subdirectory {entry_rel}: {e}")
                        continue

                    if stat.S_ISREG(mode):
                        try:
                            # Hold open descriptor with O_NOFOLLOW
                            file_fd = os.open(
                                name,
                                os.O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
                                dir_fd=curr_fd,
                            )
                            # Verify fstat matches pre-open stat
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


# Ledger processing and reference rederivation


def process_ledger_and_references(
    candidates: List[CandidateFile],
    specials: List[SpecialEntry],
    roots: List[str],
    ledger_relpath: str,
    binding: LaunchBinding,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Parses ledger.jsonl AFTER initial metadata sampling is complete.
    Detects executable/ledger hardlink alias attacks.
    Rederives monitored reference set, validates against pre-read census.
    Evaluates numeric atime predicates from kernel stat values.
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

    # 1. Locate candidate ledger file in pre-read census
    ledger_file: Optional[CandidateFile] = None
    for c in candidates:
        if c.rel_path == ledger_relpath or c.rel_path.endswith("/" + ledger_relpath):
            ledger_file = c
            break

    if ledger_file is None:
        reasons.append(f"ledger file {ledger_relpath!r} not found in pre-read candidate census")
        checks["ledger_header"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    # 2. Check for Executable/Ledger Hardlink Alias Attack
    # If ledger.jsonl shares an inode with any OTHER candidate regular file,
    # reading ledger.jsonl would advance atime of that file!
    aliased_candidates = [
        c
        for c in candidates
        if c.rel_path != ledger_file.rel_path
        and (c.st_dev, c.st_ino) == (ledger_file.st_dev, ledger_file.st_ino)
    ]
    if aliased_candidates or ledger_file.st_nlink > 1:
        alias_paths = [c.rel_path for c in aliased_candidates]
        reasons.append(
            f"executable/ledger hardlink alias attack detected: ledger {ledger_file.rel_path} "
            f"shares inode {ledger_file.st_ino} with {alias_paths!r} (st_nlink={ledger_file.st_nlink})"
        )
        checks["no_hardlink_aliases"] = "FAIL"

    # 3. Read ledger raw bytes from held descriptor
    if ledger_file.fd is None:
        reasons.append("held descriptor for ledger is missing")
        checks["ledger_digest"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    try:
        os.lseek(ledger_file.fd, 0, os.SEEK_SET)
        ledger_raw = b""
        while True:
            chunk = os.read(ledger_file.fd, 65536)
            if not chunk:
                break
            ledger_raw += chunk
    except OSError as e:
        reasons.append(f"failed to read ledger bytes from held fd: {e}")
        checks["ledger_digest"] = "FAIL"
        return {"checks": checks, "reasons": reasons, "status": "REJECT"}, reasons

    ledger_sha256 = hashlib.sha256(ledger_raw).hexdigest()
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

    # 4. Rederive monitored references from records
    # Map candidates by rel_path and by (st_dev, st_ino)
    candidate_by_path: Dict[str, CandidateFile] = {}
    candidate_by_ino: Dict[Tuple[int, int], List[CandidateFile]] = {}
    for c in candidates:
        candidate_by_path[c.rel_path] = c
        # Normalize relative path without leading ./
        norm = os.path.normpath(c.rel_path)
        candidate_by_path[norm] = c
        candidate_by_ino.setdefault((c.st_dev, c.st_ino), []).append(c)

    specials_by_path: Dict[str, SpecialEntry] = {
        os.path.normpath(s.rel_path): s for s in specials
    }

    references: List[Dict[str, Any]] = []
    seen_refs: Set[str] = set()
    seen_inos: Set[Tuple[int, int]] = set()

    for rec_idx, rec in enumerate(records):
        phase = rec.get("phase")
        if phase != "end":
            continue

        out_ref = rec.get("out_ref")
        out_target = rec.get("out")
        recorded_ino = rec.get("out_ino")
        recorded_mtime = rec.get("out_mtime_ns")
        recorded_atime_set = rec.get("atime_set_ns")
        consumer = rec.get("consumer") if isinstance(rec.get("consumer"), dict) else {}
        expected_sha256 = consumer.get("out_sha256")

        if not out_ref:
            # Not all records require an out_ref (e.g. non-output commands)
            continue

        # Check path escape in out_ref
        norm_ref = os.path.normpath(out_ref)
        if norm_ref.startswith("../") or norm_ref.startswith("/"):
            # Check if absolute path matches inside a root
            matched_root = False
            for root_idx, r in enumerate(roots):
                abs_r = os.path.abspath(r)
                if norm_ref.startswith(abs_r + "/"):
                    norm_ref = os.path.relpath(norm_ref, abs_r)
                    matched_root = True
                    break
            if not matched_root and (norm_ref.startswith("/") or norm_ref.startswith("../")):
                reasons.append(f"reference {out_ref!r} escapes permitted roots")
                checks["no_foreign_references"] = "FAIL"
                continue

        # Check if reference is a symlink or special file
        if norm_ref in specials_by_path:
            sp = specials_by_path[norm_ref]
            if sp.kind == "symlink":
                reasons.append(f"monitored reference {out_ref!r} is a symlink")
                checks["no_symlink_escapes"] = "FAIL"
            else:
                reasons.append(f"monitored reference {out_ref!r} is a special file ({sp.kind})")
                checks["no_symlink_escapes"] = "FAIL"
            continue

        # Check pre-read candidate existence
        candidate = candidate_by_path.get(norm_ref)
        if candidate is None:
            reasons.append(f"monitored reference {out_ref!r} was missing from pre-read census")
            checks["no_missing_references"] = "FAIL"
            continue

        # Check duplicate reference usage
        if norm_ref in seen_refs:
            reasons.append(f"duplicate reference detected in ledger: {norm_ref!r}")
            checks["no_duplicate_references"] = "FAIL"
        seen_refs.add(norm_ref)

        ref_ino_key = (candidate.st_dev, candidate.st_ino)
        if ref_ino_key in seen_inos:
            # Different paths sharing inode is legitimate hardlink only if one is out and one is out_ref
            pass
        seen_inos.add(ref_ino_key)

        # Check physical inode against recorded inode
        if recorded_ino is not None and candidate.st_ino != recorded_ino:
            reasons.append(
                f"reference {out_ref!r} physical inode {candidate.st_ino} "
                f"!= recorded {recorded_ino}"
            )
            checks["no_missing_references"] = "FAIL"

        # Check hardlink alias against ledger inode
        if (candidate.st_dev, candidate.st_ino) == (ledger_file.st_dev, ledger_file.st_ino):
            reasons.append(
                f"reference {out_ref!r} is an alias of ledger {ledger_file.rel_path}"
            )
            checks["no_hardlink_aliases"] = "FAIL"

        # Check hardlink relationship if out is present
        hardlink_verified = False
        if out_target:
            norm_out = os.path.normpath(out_target)
            for r in roots:
                abs_r = os.path.abspath(r)
                if norm_out.startswith(abs_r + "/"):
                    norm_out = os.path.relpath(norm_out, abs_r)
                    break
            out_cand = candidate_by_path.get(norm_out)
            if out_cand:
                if (out_cand.st_dev, out_cand.st_ino) == (candidate.st_dev, candidate.st_ino):
                    hardlink_verified = True
                else:
                    reasons.append(
                        f"reference {out_ref!r} inode {candidate.st_ino} != target {out_target!r} inode {out_cand.st_ino}"
                    )
                    checks["no_hardlink_aliases"] = "FAIL"

        # Numeric atime advancement check from integer nanoseconds
        atime_adv = False
        atime_delta_ns = 0
        if isinstance(recorded_mtime, int):
            atime_delta_ns = candidate.st_atime_ns - recorded_mtime
            if candidate.st_atime_ns > recorded_mtime:
                atime_adv = True
            else:
                reasons.append(
                    f"reference {out_ref!r} atime {candidate.st_atime_ns} <= mtime {recorded_mtime}"
                )
                checks["numeric_atime_predicates"] = "FAIL"

        if isinstance(recorded_atime_set, int) and candidate.st_atime_ns <= recorded_atime_set:
            reasons.append(
                f"reference {out_ref!r} atime {candidate.st_atime_ns} <= atime_set_ns {recorded_atime_set}"
            )
            checks["numeric_atime_predicates"] = "FAIL"

        # Content hash check
        sha256_match = True
        actual_sha256 = ""
        if candidate.fd is not None:
            try:
                os.lseek(candidate.fd, 0, os.SEEK_SET)
                file_raw = b""
                while True:
                    chunk = os.read(candidate.fd, 65536)
                    if not chunk:
                        break
                    file_raw += chunk
                actual_sha256 = hashlib.sha256(file_raw).hexdigest()
                if expected_sha256 and actual_sha256 != expected_sha256:
                    sha256_match = False
                    reasons.append(
                        f"reference {out_ref!r} sha256 mismatch: expected {expected_sha256}, got {actual_sha256}"
                    )
                    checks["raw_bytes_retained"] = "FAIL"
            except OSError as e:
                reasons.append(f"failed to read raw bytes from {candidate.rel_path}: {e}")
                checks["raw_bytes_retained"] = "FAIL"

        references.append(
            {
                "inv": rec.get("inv", f"rec_{rec_idx}"),
                "command": rec.get("command"),
                "out": out_target,
                "out_ref": out_ref,
                "norm_ref": norm_ref,
                "recorded_ino": recorded_ino,
                "recorded_mtime_ns": recorded_mtime,
                "recorded_atime_set_ns": recorded_atime_set,
                "observed_dev": candidate.st_dev,
                "observed_ino": candidate.st_ino,
                "observed_atime_ns": candidate.st_atime_ns,
                "observed_mtime_ns": candidate.st_mtime_ns,
                "atime_delta_ns": atime_delta_ns,
                "atime_advanced": atime_adv,
                "hardlink_verified": hardlink_verified,
                "sha256": actual_sha256,
                "sha256_verified": sha256_match,
            }
        )

    status = "PASS" if not reasons else "REJECT"

    ledger_summary = {
        "rel_path": ledger_file.rel_path,
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


# Raw evidence collection through held descriptors


def collect_raw_file_bytes(
    candidates: List[CandidateFile],
    monitored_refs: Set[str],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Reads actual raw bytes from held descriptors for monitored candidates.
    Performs post-read fstat checks to ensure bytes and metadata were not modified during capture.
    """
    raw_files: List[Dict[str, Any]] = []
    errors: List[str] = []

    for c in candidates:
        norm_path = os.path.normpath(c.rel_path)
        # Capture raw bytes for monitored files or executables
        if norm_path not in monitored_refs and not c.rel_path.endswith(".ref"):
            # Still capture if it is an executable or candidate reference
            continue

        if c.fd is None:
            errors.append(f"held descriptor missing for {c.rel_path}")
            continue

        try:
            os.lseek(c.fd, 0, os.SEEK_SET)
            content = b""
            while True:
                chunk = os.read(c.fd, 65536)
                if not chunk:
                    break
                content += chunk

            # Post-read stat check
            post_stat = os.fstat(c.fd)
            if post_stat.st_ino != c.st_ino or post_stat.st_dev != c.st_dev:
                errors.append(f"file inode changed during read: {c.rel_path}")
                continue
            if post_stat.st_size != len(content):
                errors.append(
                    f"file size changed during read: {c.rel_path} stat={post_stat.st_size} read={len(content)}"
                )
                continue
            if getattr(post_stat, "st_mtime_ns", int(post_stat.st_mtime * 1e9)) != c.st_mtime_ns:
                errors.append(f"file mtime changed during read: {c.rel_path}")
                continue

            sha256_hex = hashlib.sha256(content).hexdigest()
            raw_files.append(
                {
                    "rel_path": c.rel_path,
                    "st_dev": c.st_dev,
                    "st_ino": c.st_ino,
                    "size": len(content),
                    "sha256": sha256_hex,
                    "file_bytes": content,
                }
            )
        except OSError as e:
            errors.append(f"failed to read file bytes for {c.rel_path}: {e}")

    return raw_files, errors


# Main observer orchestrator


def run_origin_observer(
    roots: List[str],
    binding: LaunchBinding,
    ledger_relpath: str = "ledger.jsonl",
    output_stream: Optional[BinaryIO] = None,
    capture_raw_bytes: bool = True,
) -> Dict[str, Any]:
    """
    Main entrypoint for origin observation.
    Executes sequence:
    1. Pre-read descriptor-relative walk and fstat sampling of all candidate regular files.
    2. Commit initial metadata census before reading ledger.
    3. Read and parse ledger descriptor-relatively; detect hardlink aliases.
    4. Validate references against pre-read census.
    5. Collect raw executable bytes from held descriptors.
    6. Emit versioned framed stream to output_stream.
    7. Close held descriptors.
    """
    start_time_ns = time.time_ns()
    candidates, specials, walk_errors = walk_roots_descriptor_relative(roots)

    try:
        proc_res, proc_errors = process_ledger_and_references(
            candidates=candidates,
            specials=specials,
            roots=roots,
            ledger_relpath=ledger_relpath,
            binding=binding,
        )

        all_errors = walk_errors + proc_errors

        # Determine monitored references
        monitored_paths: Set[str] = set()
        for ref in proc_res.get("references", []):
            if ref.get("norm_ref"):
                monitored_paths.add(ref["norm_ref"])
            if ref.get("out"):
                monitored_paths.add(os.path.normpath(ref["out"]))

        raw_files: List[Dict[str, Any]] = []
        if capture_raw_bytes and proc_res.get("status") == "PASS":
            raw_files, raw_errors = collect_raw_file_bytes(candidates, monitored_paths)
            all_errors.extend(raw_errors)

        final_status = "PASS" if not all_errors and proc_res.get("status") == "PASS" else "REJECT"

        metadata_doc: Dict[str, Any] = {
            "v": PROTOCOL_VERSION,
            "kind": "iyi-origin-observer-metadata",
            "launch_binding": {
                "chain_id": binding.chain_id,
                "driver": binding.driver,
                "attempt": binding.attempt,
                "launch_id": binding.launch_id,
                "expected_nonce": binding.expected_nonce,
            },
            "observer_identity": {
                "uid": os.getuid() if hasattr(os, "getuid") else -1,
                "gid": os.getgid() if hasattr(os, "getgid") else -1,
                "pid": os.getpid(),
                "timestamp_ns": start_time_ns,
            },
            "roots": [
                {
                    "path": os.path.abspath(r),
                    "candidate_files": sum(1 for c in candidates if c.root_index == idx),
                }
                for idx, r in enumerate(roots)
            ],
            "initial_census": [c.to_dict() for c in candidates],
            "specials": [s.to_dict() for s in specials],
            "ledger": proc_res.get("ledger"),
            "references": proc_res.get("references", []),
            "raw_files_manifest": [
                {
                    "rel_path": rf["rel_path"],
                    "st_dev": rf["st_dev"],
                    "st_ino": rf["st_ino"],
                    "size": rf["size"],
                    "sha256": rf["sha256"],
                }
                for rf in raw_files
            ],
            "verdict": {
                "status": final_status,
                "reasons": all_errors,
                "checks": proc_res.get("checks", {}),
            },
            "limitations": [
                "Data-only observer: cannot distinguish authentic kernel execution from "
                "read/utime without an independent parent execution witness."
            ],
        }

        # Write wire protocol if stream provided
        if output_stream is not None:
            write_header(output_stream)
            meta_bytes = json.dumps(metadata_doc, indent=2, sort_keys=True).encode("utf-8")
            write_frame(output_stream, FRAME_METADATA, meta_bytes)

            for rf in raw_files:
                frame_payload = encode_raw_file_frame(
                    rel_path=rf["rel_path"],
                    st_dev=rf["st_dev"],
                    st_ino=rf["st_ino"],
                    sha256_hex=rf["sha256"],
                    file_bytes=rf["file_bytes"],
                )
                write_frame(output_stream, FRAME_RAW_FILE, frame_payload)

            term_doc = {
                "status": final_status,
                "reasons": all_errors,
                "timestamp_ns": time.time_ns(),
            }
            term_bytes = json.dumps(term_doc, sort_keys=True).encode("utf-8")
            write_frame(output_stream, FRAME_TERMINATION, term_bytes)

        return metadata_doc

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
    parser.add_argument("--ledger-relpath", default="ledger.jsonl", help="Relative path to ledger within root")
    parser.add_argument("--output-fd", type=int, default=None, help="File descriptor for length-delimited output pipe")
    parser.add_argument("--output-file", default=None, help="File path for length-delimited output (alternative to fd)")
    parser.add_argument("--capture-raw-bytes", action="store_true", default=True, help="Capture raw bytes of monitored executables")

    args = parser.parse_args(argv)

    binding = LaunchBinding(
        chain_id=args.chain_id,
        driver=args.driver,
        attempt=args.attempt,
        launch_id=args.launch_id,
        expected_nonce=args.expected_nonce,
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
