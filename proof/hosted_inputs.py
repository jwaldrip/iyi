#!/usr/bin/env python3
"""proof/hosted_inputs.py: Cryptographically validated offline inputs stager and verifier.

Shared contract:
- stage: validates pinned sources and full Go proxy closure from official upstreams,
  stages them into a new empty directory, and prints JSON to stdout.
  Performs descriptor-confined staging starting from trusted root anchor / using
  descriptor-relative O_NOFOLLOW traversal (openat/mkdirat/replaceat) to prevent TOCTOU escapes.
- verify: recomputes and matches authorized pinned inventory, rejecting any
  missing, extra, altered, unreadable, hardlinked, or symlinked inputs.
  Recomputes module h1/mod_h1 matching Go CheckZip and dirhash.HashZip semantics,
  and validates against the authorized lock.
  Prints the same JSON to stdout, and exits nonzero on any discrepancy.

STDOUT is reserved strictly for JSON output on success.
All diagnostic, error, and logging output goes to STDERR.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import posixpath
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


# -----------------------------------------------------------------------------
# Go module h1 calculation (golang.org/x/mod/sumdb/dirhash and golang.org/x/mod/zip)
# -----------------------------------------------------------------------------

def compute_mod_h1(mod_bytes: bytes) -> str:
    """Compute Go mod_h1 for go.mod content matching dirhash.Hash1."""
    hf = hashlib.sha256(mod_bytes).hexdigest()
    h = hashlib.sha256()
    h.update(f"{hf}  go.mod\n".encode("utf-8"))
    return "h1:" + base64.b64encode(h.digest()).decode("ascii")


def compute_zip_h1(zip_bytes: bytes, expected_prefix: str | None = None) -> str:
    """Compute Go h1 for module zip archive matching dirhash.HashZip and CheckZip.

    Faithfully enforces Go module zip invariants:
    - Rejects any filename containing newline (\\n) or carriage return (\\r)
    - Rejects duplicate filenames
    - Rejects path traversal (..) or absolute paths
    - Rejects unclean paths (e.g. ./, redundant slashes)
    - Rejects case-folding collisions
    - Rejects filenames not starting with canonical module prefix (if provided)
    - Hashes all entries in lexicographical order, including directory entries,
      matching Go dirhash.HashZip.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as e:
        raise ValueError(f"Invalid zip archive: {e}") from e

    namelist = zf.namelist()
    seen_folded: Dict[str, Tuple[str, bool]] = {}

    for name in namelist:
        if "\n" in name or "\r" in name:
            raise ValueError(f"Zip entry contains newline characters (dirhash violation): {name!r}")
        if name.startswith("/") or name.startswith("\\"):
            raise ValueError(f"Zip entry has absolute path: {name!r}")
        parts = name.split("/")
        if ".." in parts:
            raise ValueError(f"Zip entry has path traversal: {name!r}")

        if expected_prefix is not None:
            if not name.startswith(expected_prefix):
                raise ValueError(
                    f"Zip entry {name!r} does not have expected canonical module prefix {expected_prefix!r}"
                )
            sub = name[len(expected_prefix):]
            if not sub:
                continue

            is_dir = sub.endswith("/")
            clean_sub = sub[:-1] if is_dir else sub

            # Check clean path (path.Clean(name) == name check in CheckZip)
            if posixpath.normpath(clean_sub) != clean_sub or clean_sub.startswith("./") or "//" in clean_sub:
                raise ValueError(f"Zip entry has unclean path (CheckZip violation): {sub!r}")

            # Case collision check (CheckZip collisionChecker)
            fold = clean_sub.lower()
            if fold in seen_folded:
                prev_name, prev_is_dir = seen_folded[fold]
                if clean_sub != prev_name:
                    raise ValueError(
                        f"Case-insensitive file name collision in zip: {prev_name!r} and {clean_sub!r}"
                    )
                if is_dir != prev_is_dir:
                    raise ValueError(f"Entry in zip is both file and directory: {clean_sub!r}")
                if not is_dir:
                    raise ValueError(f"Duplicate entry for file in zip: {clean_sub!r}")
            else:
                seen_folded[fold] = (clean_sub, is_dir)

    # Sort files lexicographically matching slices.Sort in Go dirhash.Hash1
    h = hashlib.sha256()
    for name in sorted(namelist):
        with zf.open(name) as f:
            file_sha = hashlib.sha256(f.read()).hexdigest()
        h.update(f"{file_sha}  {name}\n".encode("utf-8"))

    return "h1:" + base64.b64encode(h.digest()).decode("ascii")


# -----------------------------------------------------------------------------
# File and Path safety utilities
# -----------------------------------------------------------------------------

def compute_file_sha256(path: Path) -> Tuple[str, int]:
    """Compute SHA-256 and size of a regular file."""
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    return hasher.hexdigest(), size


def compute_inventory_sha256(files_dict: Dict[str, Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 over all inventory file hashes and relative paths."""
    lines: List[str] = []
    for rel_path in sorted(files_dict.keys()):
        file_sha256 = files_dict[rel_path]["sha256"]
        lines.append(f"{file_sha256}  {rel_path}\n")
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def normalize_rel_path(path_str: str) -> str:
    """Normalize relative path to POSIX forward-slash style and check safety."""
    if not path_str or path_str.startswith("/") or path_str.startswith("\\"):
        raise ValueError(f"Path must be relative, got: {path_str!r}")
    norm = os.path.normpath(path_str).replace("\\", "/")
    parts = norm.split("/")
    if ".." in parts or norm.startswith("../") or norm == "..":
        raise ValueError(f"Path traversal detected: {path_str!r}")
    if os.path.isabs(norm) or (len(norm) > 1 and norm[1] == ":"):
        raise ValueError(f"Absolute path or drive letter detected: {path_str!r}")
    return norm


def check_path_ancestors_no_symlinks(path: Path) -> None:
    """Ensure that path itself and all ancestors up to root contain no symlinks.

    Walks all the way to root regardless of whether intermediate components exist,
    preventing non-existent leaves beneath symlinked ancestors from escaping inspection.
    System root mounts (/var, /tmp, /etc on macOS) are permitted.
    """
    if path.is_symlink():
        raise ValueError(f"Path itself cannot be a symlink: {path}")

    system_roots = {Path("/var"), Path("/tmp"), Path("/etc")}
    p = path.parent
    while True:
        if p.is_symlink():
            if sys.platform == "darwin" and p in system_roots:
                pass
            else:
                raise ValueError(f"Symlinked component detected in path: {p}")
        parent = p.parent
        if parent == p:
            break
        p = parent


def open_directory_descriptor_safely(path: Path, must_be_empty: bool = True) -> int:
    """Acquire a directory descriptor starting from trusted root anchor / using O_NOFOLLOW.

    Traverses step-by-step from /, creating missing components only if the parent
    descriptor is verified to be owned by the current user.
    Prevents pathname race conditions (TOCTOU) and out-of-tree redirection.
    """
    norm_path = os.path.normpath(os.path.abspath(str(path)))
    parts = [p for p in norm_path.split(os.sep) if p]

    anchor_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    curr_fd = anchor_fd

    for i, part in enumerate(parts):
        # Handle macOS system root symlinks (/var -> private/var) securely at root level
        if i == 0 and sys.platform == "darwin":
            try:
                target = os.readlink(part, dir_fd=curr_fd)
                if part in ("var", "tmp", "etc") and target in (f"private/{part}", f"/private/{part}"):
                    p1_fd = os.open("private", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=curr_fd)
                    os.close(curr_fd)
                    p2_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=p1_fd)
                    os.close(p1_fd)
                    curr_fd = p2_fd
                    continue
            except OSError:
                pass

        flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        try:
            next_fd = os.open(part, flags, dir_fd=curr_fd)
        except FileNotFoundError:
            # Component does not exist. Verify parent descriptor is owned by current user!
            st_parent = os.fstat(curr_fd)
            if st_parent.st_uid != os.getuid():
                os.close(curr_fd)
                raise PermissionError(f"Cannot create directory component {part!r} in unowned parent: uid {st_parent.st_uid} != {os.getuid()}")
            os.mkdir(part, 0o755, dir_fd=curr_fd)
            next_fd = os.open(part, flags, dir_fd=curr_fd)
        except OSError as e:
            os.close(curr_fd)
            raise ValueError(f"Failed opening path component {part!r} with O_NOFOLLOW: {e}") from e

        os.close(curr_fd)
        curr_fd = next_fd

    st_final = os.fstat(curr_fd)
    if not stat.S_ISDIR(st_final.st_mode):
        os.close(curr_fd)
        raise ValueError(f"Path is not a directory: {path}")

    if st_final.st_uid != os.getuid():
        os.close(curr_fd)
        raise PermissionError(f"Output directory not owned by current user: {path} (uid {st_final.st_uid} != {os.getuid()})")

    if must_be_empty:
        existing = os.listdir(curr_fd)
        if existing:
            os.close(curr_fd)
            raise ValueError(f"Output directory exists and is not empty ({len(existing)} entries): {path}")

    return curr_fd


# -----------------------------------------------------------------------------
# Lock validation
# -----------------------------------------------------------------------------

def load_and_validate_lock(lock_path: Path) -> Tuple[Dict[str, Any], str]:
    """Load lockfile, compute lock_sha256, and validate structure and closure."""
    if not lock_path.is_file():
        raise FileNotFoundError(f"Lock file does not exist or is not a file: {lock_path}")

    raw_bytes = lock_path.read_bytes()
    lock_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        lock_data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        raise ValueError(f"Lock file is not valid JSON: {e}") from e

    if not isinstance(lock_data, dict):
        raise ValueError("Lock file root must be a JSON object")

    schema_version = lock_data.get("schema_version")
    if schema_version != 1:
        raise ValueError(f"Unsupported lock schema_version: {schema_version}")

    files = lock_data.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Lock file must contain non-empty 'files' mapping")

    inventory_sha256 = lock_data.get("inventory_sha256")
    if not isinstance(inventory_sha256, str) or len(inventory_sha256) != 64:
        raise ValueError("Lock file must contain 64-character hex 'inventory_sha256'")

    for rel_path, meta in files.items():
        normalize_rel_path(rel_path)
        if not isinstance(meta, dict):
            raise ValueError(f"File entry {rel_path!r} must be an object")
        if "sha256" not in meta or "size" not in meta:
            raise ValueError(f"File entry {rel_path!r} must contain 'sha256' and 'size'")
        if not isinstance(meta["sha256"], str) or len(meta["sha256"]) != 64:
            raise ValueError(f"File entry {rel_path!r} has invalid sha256")
        if not isinstance(meta["size"], int) or meta["size"] < 0:
            raise ValueError(f"File entry {rel_path!r} has invalid size")

    recomputed_inv = compute_inventory_sha256(files)
    if recomputed_inv != inventory_sha256:
        raise ValueError(
            f"Lock file internal inventory_sha256 mismatch: recorded {inventory_sha256} != recomputed {recomputed_inv}"
        )

    go_modules = lock_data.get("go_modules")
    if not isinstance(go_modules, dict) or not go_modules:
        raise ValueError("Lock file missing 'go_modules' closure specification")

    for mod_key, mod_meta in go_modules.items():
        mod = mod_meta.get("module")
        ver = mod_meta.get("version")
        h1 = mod_meta.get("h1")
        mod_h1 = mod_meta.get("mod_h1")
        if not mod or not ver or not h1 or not mod_h1:
            raise ValueError(f"Invalid go_module entry for {mod_key!r}: missing required module/version/h1/mod_h1")

    return lock_data, lock_sha256


# -----------------------------------------------------------------------------
# Verification Engine
# -----------------------------------------------------------------------------

def verify_bundle_tree(input_dir: Path, lock_data: Dict[str, Any], lock_sha256: str) -> Dict[str, Any]:
    """Verify input directory strictly against lock.

    Rejects:
    - Symlinked input directory or ancestor
    - Symlinks (files or directories)
    - Special files (FIFOs, sockets, devices)
    - Hardlinked regular files (st_nlink > 1)
    - Unreadable files or unreadable directories
    - Missing files from lock
    - Unexpected extra files or unexpected directories
    - Checksum or size mismatches
    - Module h1 / mod_h1 checksum mismatches
    - Inventory SHA-256 mismatch
    """
    if input_dir.is_symlink():
        raise ValueError(f"Input path cannot be a symlink: {input_dir}")
    check_path_ancestors_no_symlinks(input_dir)

    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")
    if not input_dir.is_dir():
        raise ValueError(f"Input path is not a directory: {input_dir}")

    abs_input = input_dir.resolve()
    expected_files: Dict[str, Dict[str, Any]] = lock_data["files"]
    expected_rel_set: Set[str] = set(expected_files.keys())

    # Build valid directory prefixes
    valid_dir_prefixes: Set[str] = {"."}
    for rel in expected_rel_set:
        parts = rel.split("/")
        for i in range(1, len(parts)):
            valid_dir_prefixes.add("/".join(parts[:i]))

    found_files: Dict[str, Dict[str, Any]] = {}

    def on_walk_error(err: OSError) -> None:
        raise ValueError(f"Directory traversal error (e.g. unreadable directory or permission denied): {err}")

    for root, dirs, filenames in os.walk(abs_input, followlinks=False, onerror=on_walk_error):
        root_path = Path(root)

        if root_path.is_symlink():
            rel_dir = os.path.relpath(root_path, abs_input).replace("\\", "/")
            raise ValueError(f"Symlinked directory detected at {rel_dir!r}")

        rel_root = os.path.relpath(root_path, abs_input).replace("\\", "/")
        if rel_root != "." and rel_root not in valid_dir_prefixes:
            raise ValueError(f"Unexpected directory not belonging to locked inventory: {rel_root!r}")

        # Check subdirectories pre-descent for symlinks, unreadable permissions, and unexpected names
        for d in list(dirs):
            dir_full = root_path / d
            rel_d = os.path.relpath(dir_full, abs_input).replace("\\", "/")

            if dir_full.is_symlink():
                raise ValueError(f"Symlinked directory entry detected: {rel_d!r}")

            if rel_d not in valid_dir_prefixes:
                raise ValueError(f"Unexpected directory not in authorized lock: {rel_d!r}")

            try:
                os.listdir(dir_full)
            except (PermissionError, OSError) as e:
                raise ValueError(f"Unreadable directory detected at {rel_d!r}: {e}") from e

        for fname in filenames:
            file_path = root_path / fname
            rel_file = os.path.relpath(file_path, abs_input).replace("\\", "/")

            if file_path.is_symlink():
                raise ValueError(f"Symlinked file detected: {rel_file!r}")

            try:
                st = os.lstat(file_path)
            except OSError as e:
                raise ValueError(f"Cannot stat file {rel_file!r}: {e}") from e

            # Reject special files
            if stat.S_ISFIFO(st.st_mode):
                raise ValueError(f"FIFO special file detected: {rel_file!r}")
            if stat.S_ISSOCK(st.st_mode):
                raise ValueError(f"Socket special file detected: {rel_file!r}")
            if stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                raise ValueError(f"Device special file detected: {rel_file!r}")
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(f"Non-regular file detected: {rel_file!r} (mode {oct(st.st_mode)})")

            # Reject hardlinks with link count > 1
            if st.st_nlink > 1:
                raise ValueError(
                    f"Regular file with additional hardlinks detected: {rel_file!r} (st_nlink={st.st_nlink})"
                )

            if rel_file not in expected_rel_set:
                raise ValueError(f"Unexpected file not in authorized lock: {rel_file!r}")

            expected_meta = expected_files[rel_file]
            expected_size = expected_meta["size"]
            expected_sha = expected_meta["sha256"]

            if st.st_size != expected_size:
                raise ValueError(
                    f"File size mismatch for {rel_file!r}: disk {st.st_size} bytes != expected {expected_size} bytes"
                )

            try:
                actual_sha, actual_size = compute_file_sha256(file_path)
            except (PermissionError, OSError) as e:
                raise ValueError(f"Unreadable file detected: {rel_file!r}: {e}") from e

            if actual_size != expected_size or actual_sha != expected_sha:
                raise ValueError(
                    f"Checksum mismatch for {rel_file!r}: disk {actual_sha} != expected {expected_sha}"
                )

            found_files[rel_file] = {
                "sha256": actual_sha,
                "size": actual_size,
            }

    missing = expected_rel_set - set(found_files.keys())
    if missing:
        sample = sorted(missing)[:5]
        raise ValueError(f"Missing required file(s) from bundle ({len(missing)} missing, e.g. {sample})")

    # Validate module h1 and mod_h1 for every Go module in the bundle
    go_modules = lock_data.get("go_modules", {})
    for mod_key, mod_meta in go_modules.items():
        mod = mod_meta["module"]
        ver = mod_meta["version"]
        expected_h1 = mod_meta["h1"]
        expected_mod_h1 = mod_meta["mod_h1"]

        mod_rel = f"go-proxy/{mod}/@v/{ver}.mod"
        zip_rel = f"go-proxy/{mod}/@v/{ver}.zip"

        mod_path = abs_input / mod_rel
        zip_path = abs_input / zip_rel

        computed_mod_h1 = compute_mod_h1(mod_path.read_bytes())
        if computed_mod_h1 != expected_mod_h1:
            raise ValueError(f"Module {mod_key} mod_h1 mismatch: computed {computed_mod_h1} != expected {expected_mod_h1}")

        expected_prefix = f"{mod}@{ver}/"
        computed_zip_h1 = compute_zip_h1(zip_path.read_bytes(), expected_prefix=expected_prefix)
        if computed_zip_h1 != expected_h1:
            raise ValueError(f"Module {mod_key} zip h1 mismatch: computed {computed_zip_h1} != expected {expected_h1}")

    computed_inv_sha = compute_inventory_sha256(found_files)
    expected_inv_sha = lock_data["inventory_sha256"]
    if computed_inv_sha != expected_inv_sha:
        raise ValueError(
            f"Inventory digest mismatch: computed {computed_inv_sha} != expected {expected_inv_sha}"
        )

    return {
        "path": str(abs_input),
        "inventory_sha256": computed_inv_sha,
        "lock_sha256": lock_sha256,
        "files": found_files,
    }


# -----------------------------------------------------------------------------
# Staging Engine (Descriptor-Confined via openat/mkdirat/replaceat)
# -----------------------------------------------------------------------------

def fetch_bytes_with_retry(url: str, expected_sha256: str, expected_size: int, retries: int = 3) -> bytes:
    """Fetch bytes over HTTP/HTTPS, verifying expected size and SHA-256 digest."""
    req = urllib.request.Request(url, headers={"User-Agent": "iyi-hosted-inputs/1.0"})
    last_err: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = resp.read()
            if len(data) != expected_size:
                raise ValueError(f"Downloaded size mismatch from {url}: {len(data)} != {expected_size}")
            got_sha = hashlib.sha256(data).hexdigest()
            if got_sha != expected_sha256:
                raise ValueError(f"Downloaded SHA-256 mismatch from {url}: {got_sha} != {expected_sha256}")
            return data
        except Exception as e:
            last_err = e
            if attempt < retries:
                continue
    raise RuntimeError(f"Failed to fetch {url} after {retries} attempts: {last_err}") from last_err


def stage_bundle(
    lock_path: Path,
    output_dir: Path,
    cache_dir: Path | None = None,
    offline: bool = False,
) -> Dict[str, Any]:
    """Stage all locked files into output directory and verify the result.

    Acquires root descriptor from / using descriptor-relative O_NOFOLLOW traversal,
    and performs all child operations strictly descriptor-relative (dir_fd with O_NOFOLLOW)
    to prevent pathname races or out-of-tree redirection.
    """
    check_path_ancestors_no_symlinks(output_dir)

    lock_data, lock_sha256 = load_and_validate_lock(lock_path)
    files_to_stage = lock_data["files"]

    # Securely acquire directory descriptor starting from / with O_NOFOLLOW
    root_fd = open_directory_descriptor_safely(output_dir, must_be_empty=True)
    abs_output = output_dir.resolve()
    print(f"Staging {len(files_to_stage)} files into {abs_output} (descriptor-confined)...", file=sys.stderr)

    try:
        for rel_path in sorted(files_to_stage.keys()):
            meta = files_to_stage[rel_path]
            expected_size = meta["size"]
            expected_sha = meta["sha256"]
            source_url = meta.get("source_url")
            deterministic_content = meta.get("deterministic_content")

            rel_parts = rel_path.split("/")
            file_name = rel_parts[-1]

            # 1. Acquire data
            data: bytes | None = None

            if deterministic_content is not None:
                data = deterministic_content.encode("utf-8")
                if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha:
                    raise ValueError(f"Deterministic content mismatch for {rel_path!r}")

            if data is None and cache_dir is not None and cache_dir.is_dir():
                cache_candidate_rel = cache_dir / rel_path
                cache_candidate_hash = cache_dir / expected_sha
                for cand in [cache_candidate_rel, cache_candidate_hash]:
                    if cand.is_file() and not cand.is_symlink():
                        try:
                            cand_bytes = cand.read_bytes()
                            if len(cand_bytes) == expected_size and hashlib.sha256(cand_bytes).hexdigest() == expected_sha:
                                data = cand_bytes
                                break
                        except OSError:
                            pass

            if data is None:
                if offline:
                    raise RuntimeError(f"Offline mode requested but file {rel_path!r} not found in cache")
                if not source_url:
                    raise RuntimeError(f"No source_url for {rel_path!r} in lock")
                print(f"  Fetching {rel_path}...", file=sys.stderr)
                data = fetch_bytes_with_retry(source_url, expected_sha, expected_size)

            # 2. Traverse / create subdirectories using descriptor-relative confinement
            curr_fd = os.dup(root_fd)
            for part in rel_parts[:-1]:
                try:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=curr_fd)
                except FileNotFoundError:
                    os.mkdir(part, 0o755, dir_fd=curr_fd)
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0), dir_fd=curr_fd)
                os.close(curr_fd)
                curr_fd = next_fd

            # 3. Write atomically inside the verified directory descriptor using openat and replaceat
            tmp_name = f".tmp_{file_name}_{os.getpid()}"
            try:
                os.unlink(tmp_name, dir_fd=curr_fd)
            except OSError:
                pass

            file_fd = os.open(
                tmp_name,
                os.O_CREAT | os.O_WRONLY | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
                dir_fd=curr_fd,
            )
            try:
                os.write(file_fd, data)
            finally:
                os.close(file_fd)

            os.replace(tmp_name, file_name, src_dir_fd=curr_fd, dst_dir_fd=curr_fd)
            os.close(curr_fd)

    finally:
        os.close(root_fd)

    # 4. Strict verification of newly staged bundle
    print("Verifying staged bundle completeness, module digests, and integrity...", file=sys.stderr)
    result = verify_bundle_tree(abs_output, lock_data, lock_sha256)
    return result


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Cryptographically validated offline inputs stager and verifier for PR147 Linux proof",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: stage
    p_stage = subparsers.add_parser("stage", help="Stage validated sources and proxy closure into empty directory")
    p_stage.add_argument("--lock", required=True, type=Path, help="Path to hosted_sources.lock.json")
    p_stage.add_argument("--output", required=True, type=Path, help="Path to new empty destination directory")
    p_stage.add_argument("--cache-dir", required=False, type=Path, default=None, help="Optional local cache directory")
    p_stage.add_argument("--offline", action="store_true", default=False, help="Fail if any file not in cache")

    # Subcommand: verify
    p_verify = subparsers.add_parser("verify", help="Verify input directory against authorized lock")
    p_verify.add_argument("--lock", required=True, type=Path, help="Path to hosted_sources.lock.json")
    p_verify.add_argument("--input", required=True, type=Path, help="Path to staged inputs directory to verify")

    args = parser.parse_args(argv)

    try:
        if args.command == "stage":
            res = stage_bundle(
                lock_path=args.lock,
                output_dir=args.output,
                cache_dir=args.cache_dir,
                offline=args.offline,
            )
            # STDOUT is strictly JSON
            sys.stdout.write(json.dumps(res, indent=2) + "\n")
            sys.stdout.flush()
            return 0
        elif args.command == "verify":
            lock_data, lock_sha256 = load_and_validate_lock(args.lock)
            res = verify_bundle_tree(
                input_dir=args.input,
                lock_data=lock_data,
                lock_sha256=lock_sha256,
            )
            # STDOUT is strictly JSON
            sys.stdout.write(json.dumps(res, indent=2) + "\n")
            sys.stdout.flush()
            return 0
        else:
            parser.print_help(sys.stderr)
            return 1
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
