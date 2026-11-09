"""Bounded evidence collection and safe descriptor-relative access for hosted Linux proof.

Implements planner agent://PlanControllerRepairs:163-193, 297-312:
- Explicit finite EvidenceLimits and invocation-wide EvidenceBudget accounting.
- Descriptor-relative, no-follow, non-blocking safe stable file and directory access.
- Unique-inode bytes vs hardlink alias accounting and emitted archive bounds.
- Held inode anchor baselines preventing recycled-inode and modified-alias races.
- Depth, path, entries, descriptors, helper memory, and collection deadline enforcement.
- Canonical JSON validation with duplicate-key, non-finite number, and float-overflow rejection.
- Bounded ledger line and streamed log readers with incomplete-frame rejection.
- Bounded alias-preserving checkpoint archive creation with descriptor-relative target lifecycle.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import gzip
import hashlib
import io
import json
import math
import os
import stat
import tarfile
import time
from typing import Any, Callable, Iterator, NamedTuple, Sequence


class BoundedEvidenceError(Exception):
    """Base exception for all bounded evidence access failures."""
    pass


class EvidenceLimitExceededError(BoundedEvidenceError):
    """Raised when an explicit EvidenceLimit is exceeded."""
    pass


class EvidenceDeadlineExceededError(EvidenceLimitExceededError):
    """Raised when the collection deadline is reached or passed."""
    pass


class UnsafeEvidenceError(BoundedEvidenceError):
    """Raised when a path is unsafe (symlink, special file, invalid name, directory escape)."""
    pass


class UnstableEvidenceError(BoundedEvidenceError):
    """Raised when a file or directory changes concurrently during reading or traversal."""
    pass


class MissingEvidenceError(BoundedEvidenceError):
    """Raised when required evidence is missing."""
    pass


class IncompleteFrameError(BoundedEvidenceError):
    """Raised when a record or ledger line has an incomplete frame."""
    pass

class UnqualifiedEvidenceRuntimeError(BoundedEvidenceError):
    """The evidence collector has no qualified runtime and ownership profile."""


def _require_qualified_runtime() -> None:
    # There is no qualified allocation/compression profile or complete owned
    # collection implementation yet. Refuse before any input or output opens.
    raise UnqualifiedEvidenceRuntimeError("EVIDENCE-RUNTIME-UNQUALIFIED")


@dataclass(frozen=True)
class EvidenceLimits:
    """Explicit, finite limits for evidence collection.

    No fixed production defaults exist. All limits must be supplied explicitly
    as non-negative, finite integers (or finite float for deadline).
    """
    max_file_bytes: int
    max_unique_inode_bytes: int
    max_emitted_bytes: int
    max_entries: int
    max_aliases: int
    max_directory_depth: int
    max_path_bytes: int
    max_json_bytes: int
    max_ledger_line_bytes: int
    max_ledger_lines: int
    max_structured_records: int
    max_witness_events: int
    max_held_descriptors: int
    max_helper_memory_bytes: int
    deadline: float

    def __post_init__(self) -> None:
        int_fields = [
            "max_file_bytes",
            "max_unique_inode_bytes",
            "max_emitted_bytes",
            "max_entries",
            "max_aliases",
            "max_directory_depth",
            "max_path_bytes",
            "max_json_bytes",
            "max_ledger_line_bytes",
            "max_ledger_lines",
            "max_structured_records",
            "max_witness_events",
            "max_held_descriptors",
            "max_helper_memory_bytes",
        ]
        for name in int_fields:
            val = getattr(self, name)
            if val is None or isinstance(val, bool) or not isinstance(val, int) or val < 0:
                raise ValueError(
                    f"EvidenceLimits.{name} must be a non-negative finite integer, got {val!r}"
                )
        if (
            self.deadline is None
            or isinstance(self.deadline, bool)
            or not isinstance(self.deadline, (int, float))
            or not math.isfinite(self.deadline)
        ):
            raise ValueError(
                f"EvidenceLimits.deadline must be a finite float or int, got {self.deadline!r}"
            )

    @classmethod
    def from_timeout(
        cls,
        *,
        max_file_bytes: int,
        max_unique_inode_bytes: int,
        max_emitted_bytes: int,
        max_entries: int,
        max_aliases: int,
        max_directory_depth: int,
        max_path_bytes: int,
        max_json_bytes: int,
        max_ledger_line_bytes: int,
        max_ledger_lines: int,
        max_structured_records: int,
        max_witness_events: int,
        max_held_descriptors: int,
        max_helper_memory_bytes: int,
        timeout_seconds: float,
    ) -> EvidenceLimits:
        if (
            timeout_seconds is None
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError(
                f"timeout_seconds must be a positive finite number, got {timeout_seconds!r}"
            )
        return cls(
            max_file_bytes=max_file_bytes,
            max_unique_inode_bytes=max_unique_inode_bytes,
            max_emitted_bytes=max_emitted_bytes,
            max_entries=max_entries,
            max_aliases=max_aliases,
            max_directory_depth=max_directory_depth,
            max_path_bytes=max_path_bytes,
            max_json_bytes=max_json_bytes,
            max_ledger_line_bytes=max_ledger_line_bytes,
            max_ledger_lines=max_ledger_lines,
            max_structured_records=max_structured_records,
            max_witness_events=max_witness_events,
            max_held_descriptors=max_held_descriptors,
            max_helper_memory_bytes=max_helper_memory_bytes,
            deadline=time.monotonic() + timeout_seconds,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_unique_inode_bytes": self.max_unique_inode_bytes,
            "max_emitted_bytes": self.max_emitted_bytes,
            "max_entries": self.max_entries,
            "max_aliases": self.max_aliases,
            "max_directory_depth": self.max_directory_depth,
            "max_path_bytes": self.max_path_bytes,
            "max_json_bytes": self.max_json_bytes,
            "max_ledger_line_bytes": self.max_ledger_line_bytes,
            "max_ledger_lines": self.max_ledger_lines,
            "max_structured_records": self.max_structured_records,
            "max_witness_events": self.max_witness_events,
            "max_held_descriptors": self.max_held_descriptors,
            "max_helper_memory_bytes": self.max_helper_memory_bytes,
            "deadline": self.deadline,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceLimits:
        if not isinstance(data, dict):
            raise TypeError(f"data must be a dict, got {type(data)!r}")
        return cls(
            max_file_bytes=data["max_file_bytes"],
            max_unique_inode_bytes=data["max_unique_inode_bytes"],
            max_emitted_bytes=data["max_emitted_bytes"],
            max_entries=data["max_entries"],
            max_aliases=data["max_aliases"],
            max_directory_depth=data["max_directory_depth"],
            max_path_bytes=data["max_path_bytes"],
            max_json_bytes=data["max_json_bytes"],
            max_ledger_line_bytes=data["max_ledger_line_bytes"],
            max_ledger_lines=data["max_ledger_lines"],
            max_structured_records=data["max_structured_records"],
            max_witness_events=data["max_witness_events"],
            max_held_descriptors=data["max_held_descriptors"],
            max_helper_memory_bytes=data["max_helper_memory_bytes"],
            deadline=data["deadline"],
        )


@dataclass
class InodeAnchor:
    first_path: str
    fd: int
    st_dev: int
    st_ino: int
    st_size: int
    st_mode: int | None = None
    st_mtime_ns: int | None = None
    st_ctime_ns: int | None = None
    st_nlink: int | None = None
    sha256: str | None = None


class EvidenceBudget:
    """Invocation-wide accounting against explicit EvidenceLimits."""

    def __init__(self, limits: EvidenceLimits):
        _require_qualified_runtime()
        if not isinstance(limits, EvidenceLimits):
            raise TypeError(f"limits must be an EvidenceLimits instance, got {type(limits)!r}")
        self.limits = limits
        self.total_unique_inode_bytes = 0
        self.total_emitted_bytes = 0
        self.total_entries = 0
        self.total_aliases = 0
        self.max_observed_depth = 0
        self.total_json_bytes = 0
        self.total_ledger_line_bytes = 0
        self.total_ledger_lines = 0
        self.total_structured_records = 0
        self.total_witness_events = 0
        self.held_descriptors = 0
        self.peak_held_descriptors = 0
        self.helper_memory_bytes = 0
        self.peak_helper_memory_bytes = 0

        # Mapping of (st_dev, st_ino) -> InodeAnchor for unique-inode vs alias accounting and baseline verification
        self.seen_inodes: dict[tuple[int, int], InodeAnchor] = {}
        self._closed = False

    def __enter__(self) -> EvidenceBudget:
        if self._closed:
            raise BoundedEvidenceError("BUDGET-CLOSED")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for anchor in self.seen_inodes.values():
            os.close(anchor.fd)
            self.held_descriptors -= 1
        self.seen_inodes.clear()

    def check_deadline(self) -> None:
        if self._closed:
            raise BoundedEvidenceError("BUDGET-CLOSED")
        now = time.monotonic()
        if now >= self.limits.deadline:
            raise EvidenceDeadlineExceededError("COLLECTION-DEADLINE-EXCEEDED")

    def admit_file(self, fd: int, *, path: str) -> bool:
        """Pin a regular inode for this budget's lifetime; metadata is provisional."""
        self.check_deadline()
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UnsafeEvidenceError("SPECIAL-OR-NON-REGULAR-FILE")
        if before.st_size > self.limits.max_file_bytes:
            raise EvidenceLimitExceededError("FILE-SIZE-EXCEEDED")
        key = (before.st_dev, before.st_ino)
        baseline = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        anchor = self.seen_inodes.get(key)
        if anchor is not None:
            expected = (anchor.st_dev, anchor.st_ino, anchor.st_size, anchor.st_mode, anchor.st_mtime_ns, anchor.st_ctime_ns, anchor.st_nlink)
            if baseline(before) != expected or baseline(os.fstat(anchor.fd)) != expected:
                raise UnstableEvidenceError("ALIAS-BASELINE-MISMATCH")
            if self.total_aliases + 1 > self.limits.max_aliases:
                raise EvidenceLimitExceededError("ALIASES-EXCEEDED")
            self.total_aliases += 1
            return True
        if self.total_unique_inode_bytes + before.st_size > self.limits.max_unique_inode_bytes:
            raise EvidenceLimitExceededError("UNIQUE-INODE-BYTES-EXCEEDED")
        self.acquire_descriptor()
        try:
            pinned = os.dup(fd)
        except BaseException:
            self.release_descriptor()
            raise
        try:
            if baseline(os.fstat(pinned)) != baseline(before):
                raise UnstableEvidenceError("INODE-CHANGED-DURING-ADMISSION")
            anchor = InodeAnchor(path, pinned, before.st_dev, before.st_ino, before.st_size,
                                 before.st_mode, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
            self.seen_inodes[key] = anchor
            self.total_unique_inode_bytes += before.st_size
        except BaseException:
            os.close(pinned)
            self.release_descriptor()
            raise
        return False
    def finish_file(self, fd: int, digest: str) -> None:
        """Bind a fully consumed file to its pinned inode's first digest."""
        self.check_deadline()
        st = os.fstat(fd)
        anchor = self.seen_inodes[(st.st_dev, st.st_ino)]
        held = os.fstat(anchor.fd)
        expected = (anchor.st_dev, anchor.st_ino, anchor.st_size, anchor.st_mode, anchor.st_mtime_ns, anchor.st_ctime_ns, anchor.st_nlink)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        if identity(st) != expected or identity(held) != expected:
            raise UnstableEvidenceError("INODE-BASELINE-CHANGED")
        if anchor.sha256 is not None and anchor.sha256 != digest:
            raise UnstableEvidenceError("INODE-CONTENT-CHANGED")
        anchor.sha256 = digest

    def charge_entry(self, path: str) -> None:
        self.check_deadline()
        path_bytes = len(path.encode("utf-8"))
        if path_bytes > self.limits.max_path_bytes:
            raise EvidenceLimitExceededError(
                f"PATH-BYTES-EXCEEDED: {path!r} ({path_bytes} bytes) > max {self.limits.max_path_bytes}"
            )
        if self.total_entries + 1 > self.limits.max_entries:
            raise EvidenceLimitExceededError("ENTRIES-EXCEEDED")
        self.total_entries += 1

    def charge_directory_depth(self, depth: int) -> None:
        self.check_deadline()
        if depth > self.limits.max_directory_depth:
            raise EvidenceLimitExceededError("DIRECTORY-DEPTH-EXCEEDED")
        if depth > self.max_observed_depth:
            self.max_observed_depth = depth

    def charge_emitted_bytes(self, count: int) -> None:
        self.check_deadline()
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("INVALID-EMITTED-BYTES-CHARGE")
        new_total = self.total_emitted_bytes + count
        if new_total > self.limits.max_emitted_bytes:
            raise EvidenceLimitExceededError(
                f"EMITTED-BYTES-EXCEEDED: total emitted {new_total} > max {self.limits.max_emitted_bytes}"
            )
        self.total_emitted_bytes = new_total

    def charge_json_bytes(self, count: int) -> None:
        self.check_deadline()
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("INVALID-JSON-BYTES-CHARGE")
        new_total = self.total_json_bytes + count
        if new_total > self.limits.max_json_bytes:
            raise EvidenceLimitExceededError(
                f"JSON-BYTES-EXCEEDED: total JSON {new_total} > max {self.limits.max_json_bytes}"
            )
        self.total_json_bytes = new_total

    def charge_ledger_line(self, line: bytes | str) -> None:
        self.check_deadline()
        n = len(line) if isinstance(line, bytes) else len(line.encode("utf-8"))
        if n > self.limits.max_ledger_line_bytes:
            raise EvidenceLimitExceededError(
                f"LEDGER-LINE-BYTES-EXCEEDED: line size {n} > max {self.limits.max_ledger_line_bytes}"
            )
        if self.total_ledger_lines + 1 > self.limits.max_ledger_lines:
            raise EvidenceLimitExceededError("LEDGER-LINES-EXCEEDED")
        self.total_ledger_line_bytes += n
        self.total_ledger_lines += 1

    def charge_structured_records(self, count: int = 1) -> None:
        self.check_deadline()
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("INVALID-STRUCTURED-RECORDS-CHARGE")
        new_total = self.total_structured_records + count
        if new_total > self.limits.max_structured_records:
            raise EvidenceLimitExceededError(
                f"STRUCTURED-RECORDS-EXCEEDED: records {new_total} > max {self.limits.max_structured_records}"
            )
        self.total_structured_records = new_total

    def charge_witness_events(self, count: int = 1) -> None:
        self.check_deadline()
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("INVALID-WITNESS-EVENTS-CHARGE")
        new_total = self.total_witness_events + count
        if new_total > self.limits.max_witness_events:
            raise EvidenceLimitExceededError(
                f"WITNESS-EVENTS-EXCEEDED: witness events {new_total} > max {self.limits.max_witness_events}"
            )
        self.total_witness_events = new_total

    def acquire_descriptor(self) -> None:
        self.check_deadline()
        new_total = self.held_descriptors + 1
        if new_total > self.limits.max_held_descriptors:
            raise EvidenceLimitExceededError(
                f"HELD-DESCRIPTORS-EXCEEDED: held {new_total} > max {self.limits.max_held_descriptors}"
            )
        self.held_descriptors = new_total
        self.peak_held_descriptors = max(self.peak_held_descriptors, new_total)

    def release_descriptor(self) -> None:
        if self.held_descriptors <= 0:
            raise RuntimeError("DESCRIPTOR-ACCOUNTING-UNDERFLOW")
        self.held_descriptors -= 1

    def charge_helper_memory(self, bytes_count: int) -> None:
        self.check_deadline()
        if isinstance(bytes_count, bool) or not isinstance(bytes_count, int) or bytes_count < 0:
            raise ValueError("INVALID-HELPER-MEMORY-CHARGE")
        new_total = self.helper_memory_bytes + bytes_count
        if new_total > self.limits.max_helper_memory_bytes:
            raise EvidenceLimitExceededError(
                f"HELPER-MEMORY-EXCEEDED: memory {new_total} > max {self.limits.max_helper_memory_bytes}"
            )
        self.helper_memory_bytes = new_total
        self.peak_helper_memory_bytes = max(self.peak_helper_memory_bytes, new_total)

    def release_helper_memory(self, bytes_count: int) -> None:
        if (isinstance(bytes_count, bool) or not isinstance(bytes_count, int)
                or bytes_count < 0 or bytes_count > self.helper_memory_bytes):
            raise RuntimeError("HELPER-MEMORY-ACCOUNTING-UNDERFLOW")
        self.helper_memory_bytes -= bytes_count


def _parts(path: str) -> list[str]:
    if not path or path.startswith("/"):
        raise UnsafeEvidenceError(f"INVALID-RELATIVE-PATH: {path!r}")
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise UnsafeEvidenceError(f"INVALID-RELATIVE-PATH: {path!r}")
    return parts


def _nofollow(
    code: str,
    label: str,
    name: str,
    flags: int,
    dir_fd: int,
    mode: int = 0o600,
    budget: EvidenceBudget | None = None,
) -> int:
    """Reserve a descriptor before opening without following links."""
    if budget is not None:
        budget.acquire_descriptor()
    try:
        return os.open(name, flags | os.O_NOFOLLOW, mode, dir_fd=dir_fd)
    except BaseException as exc:
        if budget is not None:
            budget.release_descriptor()
        if isinstance(exc, OSError) and exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise UnsafeEvidenceError(f"{code} {label}: link or non-directory") from exc
        raise


def _close_tracked(budget: EvidenceBudget | None, fd: int | None) -> None:
    if fd is not None:
        try:
            os.close(fd)
        finally:
            if budget is not None:
                budget.release_descriptor()


def _parse_float(val: str) -> float:
    """Parses JSON float and rejects non-finite values (such as float overflow from 1e10000)."""
    f = float(val)
    if not math.isfinite(f):
        raise BoundedEvidenceError("NON-FINITE-JSON-NUMBER")
    return f


def _reject_constant(val: str) -> None:
    raise BoundedEvidenceError("NON-FINITE-JSON-NUMBER")


def _verify_file_stability(
    name: str,
    before: os.stat_result,
    after: os.stat_result,
    current: os.stat_result,
    count: int,
) -> None:
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode, s.st_nlink)
    if identity(before) != identity(after):
        raise UnstableEvidenceError(
            f"UNSTABLE-MEMBER: {name} (descriptor identity changed between open and close)"
        )
    if identity(before) != identity(current):
        raise UnstableEvidenceError(
            f"UNSTABLE-MEMBER: {name} (directory entry identity differs from open descriptor)"
        )
    if count != before.st_size:
        raise UnstableEvidenceError(
            f"UNSTABLE-MEMBER: {name} (bytes read {count} != stat size {before.st_size})"
        )


class OwnedRoot:
    """Safe, descriptor-relative directory handle with no-follow path traversal."""

    def __init__(self, path: str | os.PathLike[str], *, budget: EvidenceBudget | None = None, create: bool = False):
        _require_qualified_runtime()
        path_str = os.path.abspath(os.fspath(path))
        top = path_str.strip("/").split("/")[0] if path_str != "/" else ""
        if top and os.path.islink("/" + top):
            path_str = os.path.realpath("/" + top) + path_str[len(top) + 1:]
        self.path = path_str
        self.budget = budget
        self.identities: dict[str, tuple[int, int]] = {}

        if self.budget is not None:
            self.budget.acquire_descriptor()
        try:
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        except BaseException:
            if self.budget is not None:
                self.budget.release_descriptor()
            raise
        try:
            for component in path_str.strip("/").split("/"):
                if not component:
                    continue
                if create:
                    try:
                        os.mkdir(component, 0o700, dir_fd=fd)
                    except FileExistsError:
                        pass
                next_fd = _nofollow(
                    "UNSAFE-ROOT", component, component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd, budget=self.budget
                )
                if self.budget is not None:
                    self.budget.release_descriptor()
                os.close(fd)
                fd = next_fd
            self.fd: int | None = fd
        except BaseException:
            if self.budget is not None:
                self.budget.release_descriptor()
            os.close(fd)
            raise

    def close(self) -> None:
        if getattr(self, "fd", None) is not None:
            fd = self.fd
            self.fd = None
            _close_tracked(self.budget, fd)

    def __enter__(self) -> OwnedRoot:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def remember(self, name: str, fd: int) -> None:
        st = os.fstat(fd)
        identity = (st.st_dev, st.st_ino)
        previous = self.identities.setdefault(name, identity)
        if previous != identity:
            raise UnstableEvidenceError(f"REPLACED-DIRECTORY: {name}")

    def parent(self, name: str) -> tuple[int, str]:
        if self.fd is None:
            raise UnsafeEvidenceError("OwnedRoot is closed")
        parts = _parts(name)
        if self.budget is not None:
            self.budget.charge_directory_depth(len(parts) - 1)
            self.budget.charge_entry(name)

        if self.budget is not None:
            self.budget.acquire_descriptor()
        try:
            fd = os.dup(self.fd)
        except BaseException:
            if self.budget is not None:
                self.budget.release_descriptor()
            raise
        try:
            prefix: list[str] = []
            for component in parts[:-1]:
                rel = "/".join(prefix + [component])
                nxt = _nofollow(
                    "UNSAFE-ANCESTOR", rel, component, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd, budget=self.budget
                )
                try:
                    prefix.append(component)
                    self.remember(rel, nxt)
                except BaseException:
                    _close_tracked(self.budget, nxt)
                    raise
                if self.budget is not None:
                    self.budget.release_descriptor()
                os.close(fd)
                fd = nxt
            return fd, parts[-1]
        except BaseException:
            if self.budget is not None:
                self.budget.release_descriptor()
            os.close(fd)
            raise

    def walk(self, name: str = "", include: Callable[[str, bool], bool] | None = None) -> Iterator[str]:
        if self.fd is None:
            raise UnsafeEvidenceError("OwnedRoot is closed")
        if self.budget is not None:
            self.budget.check_deadline()

        if name:
            parent_fd, leaf = self.parent(name)
            try:
                fd = _nofollow("UNSAFE-MEMBER", name, leaf, os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent_fd, budget=self.budget)
            finally:
                _close_tracked(self.budget, parent_fd)
        else:
            if self.budget is not None:
                self.budget.acquire_descriptor()
            try:
                fd = os.dup(self.fd)
            except BaseException:
                if self.budget is not None:
                    self.budget.release_descriptor()
                raise

        try:
            self.remember(name, fd)
        except BaseException:
            _close_tracked(self.budget, fd)
            raise

        def visit(directory: int, rel: str, depth: int) -> Iterator[str]:
            if self.budget is not None:
                self.budget.check_deadline()
                self.budget.charge_directory_depth(depth)

            # Bound directory enumeration before sorting to avoid unbounded memory allocation.
            raw_entries: list[str] = []
            if self.budget is not None:
                self.budget.acquire_descriptor()
            try:
                dup_fd = os.dup(directory)
            except BaseException:
                if self.budget is not None:
                    self.budget.release_descriptor()
                raise

            try:
                with os.scandir(dup_fd) as it:
                    for entry in it:
                        entry_rel = f"{rel}/{entry.name}" if rel else entry.name
                        if self.budget is not None:
                            self.budget.check_deadline()
                            self.budget.charge_entry(entry_rel)
                        raw_entries.append(entry.name)
            finally:
                try:
                    os.close(dup_fd)
                except OSError:
                    pass
                if self.budget is not None:
                    self.budget.release_descriptor()

            for entry_name in sorted(raw_entries):
                relative = f"{rel}/{entry_name}" if rel else entry_name
                st = os.stat(entry_name, dir_fd=directory, follow_symlinks=False)
                is_dir = stat.S_ISDIR(st.st_mode)
                if include is not None and not include(relative, is_dir):
                    continue
                if is_dir:
                    child = _nofollow(
                        "UNSAFE-MEMBER", relative, entry_name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=directory, budget=self.budget
                    )
                    try:
                        self.remember(relative, child)
                        yield from visit(child, relative, depth + 1)
                    finally:
                        _close_tracked(self.budget, child)
                elif stat.S_ISREG(st.st_mode):
                    yield relative
                else:
                    raise UnsafeEvidenceError(f"UNSAFE-MEMBER: {relative} (non-regular file or symlink mode {oct(st.st_mode)})")

        try:
            yield from visit(fd, name, len(_parts(name)) if name else 0)
        finally:
            _close_tracked(self.budget, fd)


class BoundedEvidenceReader:
    """Descriptor-relative, safe, stable evidence reader respecting EvidenceBudget."""

    def __init__(self, root: str | os.PathLike[str] | OwnedRoot, budget: EvidenceBudget):
        if not isinstance(budget, EvidenceBudget):
            raise TypeError(f"budget must be an EvidenceBudget instance, got {type(budget)!r}")
        self.budget = budget
        if isinstance(root, OwnedRoot):
            if root.budget is not budget:
                raise ValueError("root must use the supplied invocation budget")
            self.root = root
            self._owns_root = False
        else:
            self.root = OwnedRoot(root, budget=budget)
            self._owns_root = True

    def close(self) -> None:
        if self._owns_root and self.root is not None:
            self.root.close()

    def __enter__(self) -> BoundedEvidenceReader:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def has_member(self, name: str) -> bool:
        self.budget.check_deadline()
        try:
            parent_fd, leaf = self.root.parent(name)
        except FileNotFoundError:
            return False
        try:
            st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeEvidenceError("UNSAFE-OPTIONAL-MEMBER")
            return True
        except FileNotFoundError:
            return False
        finally:
            _close_tracked(self.budget, parent_fd)

    def stat_member(self, name: str) -> os.stat_result:
        self.budget.check_deadline()
        parent_fd, leaf = self.root.parent(name)
        try:
            st = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise UnsafeEvidenceError(f"UNSAFE-MEMBER: {name} is a symlink")
            return st
        finally:
            _close_tracked(self.budget, parent_fd)

    def read_bytes(self, name: str) -> bytes:
        """Reads file bytes descriptor-relatively with stability and limit checks."""
        self.budget.check_deadline()
        self.budget.charge_entry(name)
        parent_fd, leaf = self.root.parent(name)
        try:
            fd = _nofollow("UNSAFE-MEMBER", name, leaf, os.O_RDONLY | os.O_NONBLOCK, dir_fd=parent_fd, budget=self.budget)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise UnsafeEvidenceError(f"SPECIAL-OR-NON-REGULAR-FILE: {name}")
                if before.st_size > self.budget.limits.max_file_bytes:
                    raise EvidenceLimitExceededError(
                        f"FILE-SIZE-EXCEEDED: {name} size {before.st_size} > {self.budget.limits.max_file_bytes}"
                    )
                self.budget.admit_file(fd, path=name)
                self.budget.charge_helper_memory(before.st_size)
                try:
                    chunks: list[bytes] = []
                    bytes_read = 0
                    chunk_size = min(65536, max(4096, self.budget.limits.max_file_bytes))
                    while True:
                        self.budget.check_deadline()
                        to_read = min(chunk_size, before.st_size - bytes_read + 1 if bytes_read <= before.st_size else 1)
                        if to_read <= 0:
                            extra = os.read(fd, 1)
                            if extra:
                                raise UnstableEvidenceError(f"UNSTABLE-MEMBER: {name} file grew during read")
                            break
                        data = os.read(fd, to_read)
                        if not data:
                            if bytes_read != before.st_size:
                                raise UnstableEvidenceError(
                                    f"UNSTABLE-MEMBER: {name} short read ({bytes_read} < {before.st_size})"
                                )
                            break
                        bytes_read += len(data)
                        if bytes_read > before.st_size:
                            raise UnstableEvidenceError(f"UNSTABLE-MEMBER: {name} file grew during read")
                        chunks.append(data)

                    result = b"".join(chunks)
                    if len(result) != before.st_size:
                        raise UnstableEvidenceError(
                            f"UNSTABLE-MEMBER: {name} size mismatch ({len(result)} != {before.st_size})"
                        )
                    after = os.fstat(fd)
                    current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                    _verify_file_stability(name, before, after, current, len(result))
                    self.budget.finish_file(fd, hashlib.sha256(result).hexdigest())
                    return result
                finally:
                    self.budget.release_helper_memory(before.st_size)
            finally:
                _close_tracked(self.budget, fd)
        finally:
            _close_tracked(self.budget, parent_fd)

    def read_json(self, name: str, *, required: bool = True) -> Any:
        """Reads and strictly validates canonical JSON evidence."""
        try:
            raw = self.read_bytes(name)
        except FileNotFoundError:
            if required:
                raise MissingEvidenceError(f"MISSING-REQUIRED-EVIDENCE: {name}")
            return None

        if len(raw) > self.budget.limits.max_json_bytes:
            raise EvidenceLimitExceededError(
                f"JSON-BYTES-EXCEEDED: {name} size {len(raw)} > {self.budget.limits.max_json_bytes}"
            )
        self.budget.charge_json_bytes(len(raw))

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BoundedEvidenceError(f"INVALID-UTF8-JSON: {name}") from exc

        def _object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            d: dict[str, Any] = {}
            for k, v in pairs:
                if k in d:
                    raise BoundedEvidenceError(f"DUPLICATE-JSON-KEY: {k!r} in {name}")
                d[k] = v
            return d

        try:
            data = json.loads(
                text,
                parse_float=_parse_float,
                parse_constant=_reject_constant,
                object_pairs_hook=_object_pairs_hook,
            )
        except json.JSONDecodeError as exc:
            raise BoundedEvidenceError(f"MALFORMED-JSON: {name}: {exc}") from exc

        if isinstance(data, list):
            self.budget.charge_structured_records(len(data))
        else:
            self.budget.charge_structured_records(1)
        return data

    def read_origin_records(self, name: str = "origin_records.json", *, required: bool = True) -> Any:
        return self.read_json(name, required=required)

    def read_ledger_lines(self, name: str, *, required: bool = True) -> list[str]:
        """Reads newline-delimited ledger lines with size and framing verification."""
        self.budget.check_deadline()
        self.budget.charge_entry(name)
        try:
            parent_fd, leaf = self.root.parent(name)
        except FileNotFoundError:
            if required:
                raise MissingEvidenceError(f"MISSING-REQUIRED-EVIDENCE: {name}")
            return []

        try:
            fd = _nofollow("UNSAFE-MEMBER", name, leaf, os.O_RDONLY | os.O_NONBLOCK, dir_fd=parent_fd, budget=self.budget)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise UnsafeEvidenceError(f"SPECIAL-OR-NON-REGULAR-FILE: {name}")
                if before.st_size > self.budget.limits.max_file_bytes:
                    raise EvidenceLimitExceededError(
                        f"FILE-SIZE-EXCEEDED: {name} size {before.st_size} > {self.budget.limits.max_file_bytes}"
                    )
                self.budget.admit_file(fd, path=name)

                lines: list[str] = []
                bytes_read = 0
                buffer = bytearray()
                hasher = hashlib.sha256()
                chunk_size = min(65536, max(4096, self.budget.limits.max_file_bytes))

                while True:
                    self.budget.check_deadline()
                    data = os.read(fd, chunk_size)
                    if not data:
                        break
                    bytes_read += len(data)
                    if bytes_read > before.st_size:
                        raise UnstableEvidenceError(f"UNSTABLE-MEMBER: {name} file grew during read")
                    hasher.update(data)
                    buffer.extend(data)
                    while b"\n" in buffer:
                        idx = buffer.index(b"\n")
                        line_bytes = bytes(buffer[:idx])
                        del buffer[:idx + 1]
                        self.budget.charge_ledger_line(line_bytes)
                        try:
                            lines.append(line_bytes.decode("utf-8"))
                        except UnicodeDecodeError as exc:
                            raise BoundedEvidenceError(f"INVALID-UTF8-LEDGER: {name}") from exc

                if bytes_read != before.st_size:
                    raise UnstableEvidenceError(
                        f"UNSTABLE-MEMBER: {name} short read ({bytes_read} < {before.st_size})"
                    )
                if buffer:
                    raise IncompleteFrameError(f"INCOMPLETE-FRAME: {name} missing terminal newline")

                after = os.fstat(fd)
                current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                _verify_file_stability(name, before, after, current, bytes_read)
                self.budget.finish_file(fd, hasher.hexdigest())
                return lines
            finally:
                _close_tracked(self.budget, fd)
        finally:
            _close_tracked(self.budget, parent_fd)

    def read_structured_records(self, name: str, *, required: bool = True) -> list[dict[str, Any]]:
        """Reads newline-delimited JSON records."""
        lines = self.read_ledger_lines(name, required=required)
        records: list[dict[str, Any]] = []

        def _object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            d: dict[str, Any] = {}
            for k, v in pairs:
                if k in d:
                    raise BoundedEvidenceError(f"DUPLICATE-JSON-KEY: {k!r} in {name}")
                d[k] = v
            return d

        for line_idx, line in enumerate(lines):
            try:
                rec = json.loads(
                    line,
                    parse_float=_parse_float,
                    parse_constant=_reject_constant,
                    object_pairs_hook=_object_pairs_hook,
                )
            except json.JSONDecodeError as exc:
                raise BoundedEvidenceError(f"MALFORMED-RECORD: {name}:{line_idx + 1}: {exc}") from exc
            if not isinstance(rec, dict):
                raise BoundedEvidenceError(f"INVALID-RECORD-TYPE: {name}:{line_idx + 1} expected dict, got {type(rec)!r}")
            self.budget.charge_structured_records(1)
            records.append(rec)
        return records

    def read_streamed_log(self, name: str, *, chunk_size: int = 65536) -> Iterator[bytes]:
        """Streams log bytes in bounded chunks with post-stream stability validation."""
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("invalid chunk size")
        self.budget.check_deadline()
        self.budget.charge_entry(name)
        parent_fd, leaf = self.root.parent(name)
        try:
            fd = _nofollow("UNSAFE-MEMBER", name, leaf, os.O_RDONLY | os.O_NONBLOCK, dir_fd=parent_fd, budget=self.budget)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise UnsafeEvidenceError(f"SPECIAL-OR-NON-REGULAR-FILE: {name}")
                if before.st_size > self.budget.limits.max_file_bytes:
                    raise EvidenceLimitExceededError(
                        f"FILE-SIZE-EXCEEDED: {name} size {before.st_size} > {self.budget.limits.max_file_bytes}"
                    )
                self.budget.admit_file(fd, path=name)

                bytes_read = 0
                hasher = hashlib.sha256()
                step = min(chunk_size, max(4096, self.budget.limits.max_file_bytes))
                while True:
                    self.budget.check_deadline()
                    data = os.read(fd, step)
                    if not data:
                        break
                    bytes_read += len(data)
                    if bytes_read > before.st_size:
                        raise UnstableEvidenceError(f"UNSTABLE-MEMBER: {name} file grew during streaming")
                    hasher.update(data)
                    yield data

                if bytes_read != before.st_size:
                    raise UnstableEvidenceError(
                        f"UNSTABLE-MEMBER: {name} short read ({bytes_read} < {before.st_size})"
                    )
                after = os.fstat(fd)
                current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                _verify_file_stability(name, before, after, current, bytes_read)
                self.budget.finish_file(fd, hasher.hexdigest())
            finally:
                _close_tracked(self.budget, fd)
        finally:
            _close_tracked(self.budget, parent_fd)

    def walk(self, name: str = "", include: Callable[[str, bool], bool] | None = None) -> Iterator[str]:
        self.budget.check_deadline()
        yield from self.root.walk(name, include)


@dataclass(frozen=True)
class ArchiveMember:
    root: OwnedRoot
    name: str
    arcname: str
    optional: bool = False


@dataclass(frozen=True)
class _ArchiveMemberAnchor:
    first_arcname: str
    size: int
    sha256: str


class ArchiveResult(NamedTuple):
    path: str
    archive_bytes: int
    archive_sha256: str
    manifest: dict[str, Any]


def create_checkpoint_archive(
    target_path: str | os.PathLike[str],
    members: Sequence[ArchiveMember | tuple[Any, ...]],
    budget: EvidenceBudget,
    *,
    manifest_arcname: str = "evidence-manifest.json",
    extra_manifest: dict[str, Any] | None = None,
    store_hardlinks_as_links: bool = True,
) -> ArchiveResult:
    """Creates a bounded checkpoint archive enforcing EvidenceLimits and preserving hardlink aliases."""
    budget.check_deadline()
    target_path_str = os.path.abspath(os.fspath(target_path))
    parent_dir, leaf_name = os.path.split(target_path_str)
    if not leaf_name:
        raise UnsafeEvidenceError(f"INVALID-ARCHIVE-TARGET-PATH: {target_path_str}")

    # Validate and reserve manifest arcname
    _parts(manifest_arcname)
    budget.charge_entry(manifest_arcname)

    # Validate extra_manifest does not overwrite reserved manifest keys
    if extra_manifest is not None:
        if not isinstance(extra_manifest, dict):
            raise TypeError(f"extra_manifest must be a dict, got {type(extra_manifest)!r}")
        for reserved_key in ("version", "members"):
            if reserved_key in extra_manifest:
                raise BoundedEvidenceError(
                    f"EXTRA-MANIFEST-RESERVED-KEY: extra_manifest cannot overwrite reserved key {reserved_key!r}"
                )
        try:
            json.dumps(extra_manifest, allow_nan=False)
        except (ValueError, TypeError) as exc:
            raise BoundedEvidenceError(f"INVALID-EXTRA-MANIFEST: {exc}") from exc

    # Open parent directory descriptor-relatively using OwnedRoot to hold parent_dir fd throughout
    parent_root = OwnedRoot(parent_dir, budget=budget)
    target_fd: int | None = None
    created = False

    class BoundedOutputStream(io.RawIOBase):
        def __init__(self, fd: int, budget: EvidenceBudget):
            self.fd = fd
            self.budget = budget
            self.count = 0

        def write(self, b: bytes) -> int:
            self.budget.check_deadline()
            n = len(b)
            self.budget.charge_emitted_bytes(n)
            written = 0
            while written < n:
                self.budget.check_deadline()
                w = os.write(self.fd, b[written:])
                if w <= 0:
                    raise BoundedEvidenceError("ARCHIVE-WRITE-NO-PROGRESS")
                written += w
            self.count += n
            return n

    try:
        try:
            target_fd = _nofollow(
                "UNSAFE-ARCHIVE-TARGET",
                leaf_name,
                leaf_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                dir_fd=parent_root.fd,
                budget=budget,
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise BoundedEvidenceError(f"ARCHIVE-TARGET-EXISTS: {target_path_str}") from exc
            raise

        st_created = os.fstat(target_fd)
        target_stream = BoundedOutputStream(target_fd, budget)

        # Archive-local inode anchor map to avoid leaking archive-specific arcnames into invocation-wide budget
        archive_seen_inodes: dict[tuple[int, int], _ArchiveMemberAnchor] = {}

        with gzip.GzipFile(fileobj=target_stream, mode="wb", mtime=0.0) as gz_out:
            with tarfile.open(fileobj=gz_out, mode="w", format=tarfile.PAX_FORMAT) as tar:
                manifest_entries: list[dict[str, Any]] = []
                seen_arcnames: set[str] = set()

                for item in members:
                    budget.check_deadline()
                    if isinstance(item, ArchiveMember):
                        m_root, m_name, m_arcname, m_optional = item.root, item.name, item.arcname, item.optional
                    elif isinstance(item, (list, tuple)):
                        m_root, m_name, m_arcname = item[0], item[1], item[2]
                        m_optional = item[3] if len(item) > 3 else False
                    else:
                        raise TypeError(f"Invalid member specification: {item!r}")

                    _parts(m_arcname)
                    budget.charge_entry(m_arcname)
                    if m_arcname == manifest_arcname:
                        raise BoundedEvidenceError(
                            f"RESERVED-MANIFEST-COLLISION: member {m_arcname} collides with reserved manifest arcname"
                        )
                    if m_arcname in seen_arcnames:
                        raise BoundedEvidenceError(f"DUPLICATE-ARCHIVE-MEMBER: {m_arcname}")
                    seen_arcnames.add(m_arcname)

                    if not isinstance(m_root, OwnedRoot) or m_root.budget is not budget:
                        raise ValueError("archive root must use the supplied invocation budget")
                    try:
                        parent_fd, leaf = m_root.parent(m_name)
                    except FileNotFoundError:
                        if m_optional:
                            continue
                        raise MissingEvidenceError(f"MISSING-REQUIRED-MEMBER: {m_name}")

                    try:
                        try:
                            fd = _nofollow("UNSAFE-MEMBER", m_name, leaf, os.O_RDONLY | os.O_NONBLOCK, dir_fd=parent_fd, budget=budget)
                        except FileNotFoundError:
                            if m_optional:
                                continue
                            raise MissingEvidenceError(f"MISSING-REQUIRED-MEMBER: {m_name}")

                        try:
                            before = os.fstat(fd)
                            if not stat.S_ISREG(before.st_mode):
                                raise UnsafeEvidenceError(f"SPECIAL-OR-NON-REGULAR-FILE: {m_name}")
                            if before.st_size > budget.limits.max_file_bytes:
                                raise EvidenceLimitExceededError(
                                    f"FILE-SIZE-EXCEEDED: {m_name} size {before.st_size} > {budget.limits.max_file_bytes}"
                                )

                            inode_key = (before.st_dev, before.st_ino)
                            is_archive_alias = inode_key in archive_seen_inodes

                            budget.admit_file(fd, path=m_arcname)
                            if not is_archive_alias:
                                info = tarfile.TarInfo(m_arcname)
                                info.type = tarfile.REGTYPE
                                info.size = before.st_size
                                info.mode = 0o644
                                info.mtime = 0

                                hasher = hashlib.sha256()
                                bytes_written = 0

                                class StreamSink:
                                    def read(self, size: int = -1) -> bytes:
                                        nonlocal bytes_written
                                        budget.check_deadline()
                                        to_read = 65536 if size < 0 else min(size, 65536)
                                        chunk = os.read(fd, to_read)
                                        if chunk:
                                            bytes_written += len(chunk)
                                            hasher.update(chunk)
                                        return chunk

                                tar.addfile(info, StreamSink())
                                if bytes_written != before.st_size:
                                    raise UnstableEvidenceError(
                                        f"UNSTABLE-MEMBER: {m_name} short read ({bytes_written} != {before.st_size})"
                                    )
                                digest = hasher.hexdigest()
                                archive_seen_inodes[inode_key] = _ArchiveMemberAnchor(
                                    first_arcname=m_arcname,
                                    size=before.st_size,
                                    sha256=digest,
                                )
                                manifest_entries.append({
                                    "path": m_arcname,
                                    "bytes": bytes_written,
                                    "sha256": digest,
                                })
                            else:
                                local_anchor = archive_seen_inodes[inode_key]
                                alias_hasher = hashlib.sha256()
                                alias_count = 0
                                while alias_count < before.st_size:
                                    budget.check_deadline()
                                    chunk = os.read(fd, min(65536, before.st_size - alias_count))
                                    if not chunk:
                                        raise UnstableEvidenceError("ALIAS-SHORT-READ")
                                    alias_count += len(chunk)
                                    alias_hasher.update(chunk)
                                digest = alias_hasher.hexdigest()
                                if digest != local_anchor.sha256:
                                    raise UnstableEvidenceError("ALIAS-CONTENT-CHANGED")
                                os.lseek(fd, 0, os.SEEK_SET)

                                if store_hardlinks_as_links and local_anchor.first_arcname:
                                    info = tarfile.TarInfo(m_arcname)
                                    info.type = tarfile.LNKTYPE
                                    info.linkname = local_anchor.first_arcname
                                    info.size = 0
                                    info.mode = 0o644
                                    info.mtime = 0
                                    tar.addfile(info)
                                    manifest_entries.append({
                                        "path": m_arcname,
                                        "bytes": local_anchor.size,
                                        "sha256": local_anchor.sha256,
                                        "linkpath": local_anchor.first_arcname,
                                    })
                                else:
                                    info = tarfile.TarInfo(m_arcname)
                                    info.type = tarfile.REGTYPE
                                    info.size = before.st_size
                                    info.mode = 0o644
                                    info.mtime = 0

                                    hasher = hashlib.sha256()
                                    bytes_written = 0

                                    class StreamSink:
                                        def read(self, size: int = -1) -> bytes:
                                            nonlocal bytes_written
                                            budget.check_deadline()
                                            to_read = 65536 if size < 0 else min(size, 65536)
                                            chunk = os.read(fd, to_read)
                                            if chunk:
                                                bytes_written += len(chunk)
                                                hasher.update(chunk)
                                            return chunk

                                    tar.addfile(info, StreamSink())
                                    digest = hasher.hexdigest()
                                    manifest_entries.append({
                                        "path": m_arcname,
                                        "bytes": bytes_written,
                                        "sha256": digest,
                                    })

                            after = os.fstat(fd)
                            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                            _verify_file_stability(m_name, before, after, current, before.st_size)
                            budget.finish_file(fd, digest)
                        finally:
                            _close_tracked(budget, fd)
                    finally:
                        _close_tracked(budget, parent_fd)

                # Assemble manifest document
                manifest_doc: dict[str, Any] = {
                    "version": 1,
                    "members": manifest_entries,
                }
                if extra_manifest:
                    manifest_doc.update(extra_manifest)
                manifest_bytes = json.dumps(manifest_doc, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

                if len(manifest_bytes) > budget.limits.max_file_bytes:
                    raise EvidenceLimitExceededError(
                        f"MANIFEST-FILE-SIZE-EXCEEDED: {len(manifest_bytes)} > {budget.limits.max_file_bytes}"
                    )
                if len(manifest_bytes) > budget.limits.max_json_bytes:
                    raise EvidenceLimitExceededError(
                        f"MANIFEST-JSON-SIZE-EXCEEDED: {len(manifest_bytes)} > {budget.limits.max_json_bytes}"
                    )
                budget.charge_json_bytes(len(manifest_bytes))

                m_info = tarfile.TarInfo(manifest_arcname)
                m_info.type = tarfile.REGTYPE
                m_info.size = len(manifest_bytes)
                m_info.mode = 0o644
                m_info.mtime = 0
                tar.addfile(m_info, io.BytesIO(manifest_bytes))

        os.fsync(target_fd)
        _close_tracked(budget, target_fd)
        target_fd = None
        created = True

        # Descriptor-relative re-read using held parent_root.fd to verify exact identity and compute hash
        read_fd = _nofollow("UNSAFE-ARCHIVE-TARGET", leaf_name, leaf_name, os.O_RDONLY, dir_fd=parent_root.fd, budget=budget)
        try:
            st_read = os.fstat(read_fd)
            if (st_created.st_dev, st_created.st_ino) != (st_read.st_dev, st_read.st_ino):
                raise UnstableEvidenceError(f"ARCHIVE-TARGET-REPLACED: {leaf_name}")

            h = hashlib.sha256()
            total_read = 0
            while True:
                budget.check_deadline()
                chunk = os.read(read_fd, 65536)
                if not chunk:
                    break
                h.update(chunk)
                total_read += len(chunk)
            if total_read != st_read.st_size:
                raise UnstableEvidenceError(f"ARCHIVE-UNSTABLE: read {total_read} != stat {st_read.st_size}")
            return ArchiveResult(
                path=target_path_str,
                archive_bytes=total_read,
                archive_sha256=h.hexdigest(),
                manifest=manifest_doc,
            )
        finally:
            _close_tracked(budget, read_fd)
    except BaseException:
        if target_fd is not None:
            _close_tracked(budget, target_fd)
            target_fd = None
        # Do not unlink by name: a concurrent replacement could make the name
        # refer to a different file. The caller must handle incomplete output.
        raise
    finally:
        parent_root.close()


__all__ = [
    "EvidenceLimits",
    "EvidenceBudget",
    "BoundedEvidenceReader",
    "create_checkpoint_archive",
    "ArchiveMember",
    "ArchiveResult",
    "OwnedRoot",
    "BoundedEvidenceError",
    "EvidenceLimitExceededError",
    "EvidenceDeadlineExceededError",
    "UnsafeEvidenceError",
    "UnstableEvidenceError",
    "MissingEvidenceError",
    "IncompleteFrameError",
]
