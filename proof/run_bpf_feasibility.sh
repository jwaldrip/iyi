#!/usr/bin/env bash
# proof/run_bpf_feasibility.sh: One shared unprivileged build, artifact validation,
# and restricted launcher entry point for BPF kernel feasibility diagnostics.
# Implements sections 4, 5, and 7 of agent://PlanBpfOwnedDependencies.

set -euo pipefail

# Refuse root execution at script entry (including build-only mode)
if [ "$(id -u)" -eq 0 ] || [ "$(id -g)" -eq 0 ]; then
  echo "ERROR: Refusing to execute as root UID 0 or GID 0 (including build-only mode)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Sanitize environment: clean trusted PATH and isolated Python configuration
export PATH="/usr/bin:/bin"
export LC_ALL=C
unset PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONOPTIMIZE
unset CPATH C_INCLUDE_PATH LIBRARY_PATH LD_LIBRARY_PATH LD_PRELOAD LD_AUDIT CFLAGS LDFLAGS PKG_CONFIG_PATH

# Check for unexpected preload configuration
if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
  echo "ERROR: /etc/ld.so.preload exists and is non-empty; unexpected preload configuration" >&2
  exit 1
fi

# Bind exact approved repository lock and consumer paths (no relative CWD or arbitrary script substitution)
DEFAULT_LOCK_FILE="$REPO_ROOT/proof/bpf_dependencies.lock.json"
DEP_SCRIPT="$REPO_ROOT/proof/bpf_dependencies.py"

usage() {
  cat <<'EOF'
Usage: proof/run_bpf_feasibility.sh [OPTIONS]

Options:
  --owned-dir <path>        Scratch directory for build artifacts and reports
  --status <path>           Path to write bpf-feasibility.json report
  --build-only              Perform build and artifact validation only; skip setpriv/helper launch
  --e3-build-only           Build E3 witness and run synthetic validator tests only
  --skip-launch             Alias for --build-only
  --verbose                 Enable verbose progress logging
  -h, --help                Show this help message and exit

Internal production gate sub-actions (for direct test verification):
  --validate-bpf-obj <readelf_bin> <bpf_obj> <bpf_dep> <clang_res> <staged_prefix> <repo_root> <lock_file>
  --validate-host-elf <readelf_bin> <host_bin> <host_dep> <clang_res> <staged_prefix> <repo_root> <owned_dir> <lock_file>
  --evaluate-report <status_file>
  --validate-staged-manifest <lock_file> <receipt_file> <staged_prefix>
EOF
}

# --- Production Gate Sub-actions (shared across CLI and tests) ---

validate_staged_manifest_main() {
  python3 -I - <<'PY' "$@"
import hashlib, json, os, pathlib, sys

lock_path = pathlib.Path(sys.argv[1]).resolve()
receipt_path = pathlib.Path(sys.argv[2]).resolve()
prefix_path = pathlib.Path(sys.argv[3]).resolve()

if not lock_path.is_file():
    sys.exit(f"ERROR: Lock file '{lock_path}' does not exist")
if not receipt_path.is_file():
    sys.exit(f"ERROR: Dependency receipt '{receipt_path}' does not exist")
if not prefix_path.is_dir():
    sys.exit(f"ERROR: Staged prefix '{prefix_path}' is not a directory")

forbidden = [pathlib.Path("/"), pathlib.Path("/usr"), pathlib.Path("/etc"), pathlib.Path("/var"), pathlib.Path("/bin"), pathlib.Path("/lib")]
if prefix_path in forbidden or prefix_path.parent in [pathlib.Path("/"), pathlib.Path("/usr")]:
    sys.exit(f"ERROR: Staged prefix '{prefix_path}' is an unsafe or system root")

with open(lock_path, "r", encoding="utf-8") as f:
    lock_data = f.read()
    lock = json.loads(lock_data)
lock_sha = hashlib.sha256(lock_data.encode("utf-8")).hexdigest()

with open(receipt_path, "r", encoding="utf-8") as f:
    receipt = json.load(f)

# 1. Verify receipt status
status = receipt.get("status")
if status not in ("SUCCESS", "VERIFIED"):
    sys.exit(f"ERROR: Dependency receipt status is '{status}', expected SUCCESS or VERIFIED")

# 2. Verify snapshot identity matches lock
rec_snap = receipt.get("snapshot_id")
expected_snap = lock.get("snapshot", {}).get("snapshot_id")
if not rec_snap or rec_snap != expected_snap:
    sys.exit(f"ERROR: Receipt snapshot_id mismatch: '{rec_snap}' != '{expected_snap}'")

# 3. Verify receipt source_lock_sha256 if present
rec_lock_sha = receipt.get("source_lock_sha256")
if rec_lock_sha and rec_lock_sha.lower() != lock_sha.lower():
    sys.exit(f"ERROR: Receipt source_lock_sha256 mismatch: {rec_lock_sha} != {lock_sha}")

# 4. Verify signer fingerprint against lock trust root
approved_signers = lock.get("trust_root", {}).get("approved_signer_fingerprints", [])
receipt_signer = receipt.get("signer_fingerprint")
if not receipt_signer or receipt_signer not in approved_signers:
    sys.exit(f"ERROR: Receipt signer '{receipt_signer}' not in approved signers: {approved_signers}")

# 5. Verify receipt prefix matches actual prefix
receipt_prefix_str = receipt.get("staged_prefix") or receipt.get("prefix")
if not receipt_prefix_str:
    sys.exit("ERROR: Receipt missing staged_prefix")
receipt_prefix = pathlib.Path(receipt_prefix_str).resolve()
if receipt_prefix != prefix_path:
    sys.exit(f"ERROR: Receipt prefix '{receipt_prefix}' does not match actual prefix '{prefix_path}'")

# 6. Authoritative staged file hash and size verification against locked manifest
packages = lock.get("packages", {})
required_pkgs = ["libbpf-dev", "libelf-dev", "libzstd-dev", "zlib1g-dev"]
for pkg in required_pkgs:
    if pkg not in packages:
        sys.exit(f"ERROR: Required package '{pkg}' missing from dependency lock")
    pkg_info = packages[pkg]

    # Check deb digest in receipt: MANDATORY, not optional
    rec_packages = receipt.get("packages") or receipt.get("archives") or {}
    rec_pkg = rec_packages.get(pkg)
    if not rec_pkg:
        sys.exit(f"ERROR: Package '{pkg}' missing from receipt packages summary")

    rec_deb_sha = rec_pkg.get("sha256") or rec_pkg.get("deb_sha256") if isinstance(rec_pkg, dict) else (rec_pkg if isinstance(rec_pkg, str) else None)
    if not rec_deb_sha:
        sys.exit(f"ERROR: Receipt missing required deb SHA256 for package '{pkg}'")
    if rec_deb_sha.lower() != pkg_info.get("sha256", "").lower():
        sys.exit(f"ERROR: Receipt deb SHA256 mismatch for '{pkg}': {rec_deb_sha} != {pkg_info.get('sha256')}")

    # Verify all required static archives on disk against lock definition
    artifacts = pkg_info.get("required_artifacts", [])
    if not artifacts:
        sys.exit(f"ERROR: Package '{pkg}' has no required_artifacts in lock")
    for art in artifacts:
        rel_path = art["path"]
        expected_sha = art["sha256"]
        expected_size = art.get("size")

        full_path = prefix_path / rel_path
        if not full_path.is_file():
            sys.exit(f"ERROR: Required staged archive missing: '{rel_path}' (fail-closed, no host fallback)")

        file_bytes = full_path.read_bytes()
        actual_size = len(file_bytes)
        actual_sha = hashlib.sha256(file_bytes).hexdigest()

        if expected_size is not None and actual_size != expected_size:
            sys.exit(f"ERROR: Staged archive '{rel_path}' size mismatch: actual {actual_size} != expected {expected_size}")

        if actual_sha.lower() != expected_sha.lower():
            sys.exit(f"ERROR: Staged archive '{rel_path}' SHA256 TAMPERING DETECTED!\n  Actual:   {actual_sha}\n  Expected: {expected_sha}")

    # Verify all required headers exist on disk and match expected SHA256 and size from lock (no string/None fallback)
    headers = pkg_info.get("required_headers", [])
    if not isinstance(headers, list) or len(headers) == 0:
        sys.exit(f"ERROR: Package '{pkg}' required_headers must be non-empty list")
    for hdr in headers:
        if not isinstance(hdr, dict):
            sys.exit(f"ERROR: Package '{pkg}' required_header must be a dict: {repr(hdr)}")
        rel_hdr = hdr.get("path")
        expected_hdr_sha = hdr.get("sha256")
        expected_hdr_size = hdr.get("size")
        if not rel_hdr or not expected_hdr_sha or not isinstance(expected_hdr_size, int) or expected_hdr_size <= 0:
            sys.exit(f"ERROR: Package '{pkg}' required_header missing valid path, size, or sha256: {hdr}")
        if len(expected_hdr_sha) != 64:
            sys.exit(f"ERROR: Package '{pkg}' required_header sha256 must be 64-hex string: {expected_hdr_sha}")

        hdr_path = prefix_path / rel_hdr
        if not hdr_path.is_file():
            sys.exit(f"ERROR: Required header '{rel_hdr}' missing from staged prefix (fail-closed, no host fallback)")

        hdr_bytes = hdr_path.read_bytes()
        actual_hdr_size = len(hdr_bytes)
        actual_hdr_sha = hashlib.sha256(hdr_bytes).hexdigest()

        if actual_hdr_size != expected_hdr_size:
            sys.exit(f"ERROR: Staged header '{rel_hdr}' size mismatch: actual {actual_hdr_size} != expected {expected_hdr_size}")

        if actual_hdr_sha.lower() != expected_hdr_sha.lower():
            sys.exit(f"ERROR: Staged header '{rel_hdr}' SHA256 TAMPERING DETECTED!\n  Actual:   {actual_hdr_sha}\n  Expected: {expected_hdr_sha}")

print("Independent verification: all staged archives, deb hashes, and headers cryptographically bound to authenticated lock.")
PY
}

validate_bpf_obj_main() {
  python3 -I - <<'PY' "$@"
import hashlib, json, os, pathlib, subprocess, sys

readelf_bin = sys.argv[1]
bpf_obj = sys.argv[2]
bpf_dep = sys.argv[3]
clang_res = sys.argv[4]
prefix = sys.argv[5]
repo_root = sys.argv[6]
lock_file = sys.argv[7]
profile = sys.argv[9] if len(sys.argv) > 9 else "canary"
if profile not in ("canary", "e3"):
    sys.exit("ERROR: unknown BPF validation profile")

prefix_path = pathlib.Path(prefix).resolve()
repo_path = pathlib.Path(repo_root).resolve()

with open(lock_file, "r", encoding="utf-8") as f:
    lock = json.load(f)

all_locked_headers = {}
for pkg_name, pkg_data in lock.get("packages", {}).items():
    for hdr in pkg_data.get("required_headers", []):
        if isinstance(hdr, dict):
            all_locked_headers[hdr["path"]] = hdr
        else:
            all_locked_headers[hdr] = {"path": hdr}

def run_readelf(*args):
    cmd = [readelf_bin] + list(args)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        sys.exit(f"ERROR: readelf command failed: {' '.join(cmd)}\n{res.stderr}")
    return res.stdout

# --- Validate BPF Object ---
bpf_hdr = run_readelf("-hW", bpf_obj)
if "ELF64" not in bpf_hdr:
    sys.exit("ERROR: BPF object is not ELF64")
if "little endian" not in bpf_hdr:
    sys.exit("ERROR: BPF object is not little-endian")
if "BPF" not in bpf_hdr:
    sys.exit("ERROR: BPF object machine is not BPF")

bpf_sec = run_readelf("-SW", bpf_obj)
for sec in ["tp_btf/sched_process_exec", ".maps", "license", ".BTF", ".BTF.ext"]:
    if sec not in bpf_sec:
        sys.exit(f"ERROR: BPF object missing required section: '{sec}'")

bpf_sym = run_readelf("-sW", bpf_obj)
expected_program = "e3_sched_process_exec" if profile == "e3" else "sched_process_exec"
symbols = {line.split()[7] for line in bpf_sym.splitlines() if len(line.split()) >= 8}
if expected_program not in symbols:
    sys.exit(f"ERROR: BPF object missing expected program symbol '{expected_program}'")
if profile == "e3" and not {"e3_state", "e3_events"} <= symbols:
    sys.exit("ERROR: E3 BPF maps missing")

# Section 5: Parse real .BTF and .BTF.ext CO-RE relocation records directly from binary ELF structure
with open(bpf_obj, "rb") as f:
    bpf_raw = f.read()

if len(bpf_raw) < 64 or bpf_raw[:4] != b"\x7fELF":
    sys.exit("ERROR: BPF object is not a valid ELF file")

e_shoff = int.from_bytes(bpf_raw[40:48], "little")
e_shentsize = int.from_bytes(bpf_raw[58:60], "little")
e_shnum = int.from_bytes(bpf_raw[60:62], "little")
e_shstrndx = int.from_bytes(bpf_raw[62:64], "little")

if e_shstrndx >= e_shnum:
    sys.exit("ERROR: Invalid section string table index in BPF object")

shstr_hdr = bpf_raw[e_shoff + e_shstrndx * e_shentsize : e_shoff + (e_shstrndx + 1) * e_shentsize]
shstr_offset = int.from_bytes(shstr_hdr[24:32], "little")
shstr_size = int.from_bytes(shstr_hdr[32:40], "little")
shstrtab = bpf_raw[shstr_offset : shstr_offset + shstr_size]

sections = {}
section_indices = {}
section_flags = {}
for i in range(e_shnum):
    sh = bpf_raw[e_shoff + i * e_shentsize : e_shoff + (i + 1) * e_shentsize]
    name_off = int.from_bytes(sh[0:4], "little")
    name = shstrtab[name_off:].split(b"\x00", 1)[0].decode("latin1")
    sh_offset = int.from_bytes(sh[24:32], "little")
    sh_size = int.from_bytes(sh[32:40], "little")
    section_indices[name] = i
    section_flags[name] = int.from_bytes(sh[8:16], "little")
    sections[name] = bpf_raw[sh_offset : sh_offset + sh_size]

if profile == "e3":
    if not section_flags["tp_btf/sched_process_exec"] & 4 or not sections[".maps"]:
        sys.exit("ERROR: E3 program section is not executable or maps section empty")
    for symbol, kind, section in (("e3_sched_process_exec", "FUNC", "tp_btf/sched_process_exec"),
                                  ("e3_state", "OBJECT", ".maps"), ("e3_events", "OBJECT", ".maps")):
        matches = [p for line in bpf_sym.splitlines() if len(p := line.split()) >= 8 and p[7] == symbol]
        if len(matches) != 1 or matches[0][3] != kind or matches[0][6] != str(section_indices[section]) or int(matches[0][2]) == 0:
            sys.exit(f"ERROR: E3 symbol definition invalid: {symbol}")

# --- Parse .BTF string and type table ---
if ".BTF" not in sections:
    sys.exit("ERROR: .BTF section missing from BPF object")

btf_raw = sections[".BTF"]
if len(btf_raw) < 24:
    sys.exit("ERROR: .BTF section too short (expected at least 24-byte header)")

btf_hdr_magic = int.from_bytes(btf_raw[0:2], "little")
if btf_hdr_magic != 0xEB9F:
    sys.exit(f"ERROR: .BTF magic mismatch: 0x{btf_hdr_magic:04x}")

btf_version = btf_raw[2]
if btf_version != 1:
    sys.exit(f"ERROR: .BTF version mismatch: expected 1, got {btf_version}")

btf_hdr_len = int.from_bytes(btf_raw[4:8], "little")
if btf_hdr_len < 24:
    sys.exit(f"ERROR: .BTF header length {btf_hdr_len} too small (expected >= 24)")
if len(btf_raw) < btf_hdr_len:
    sys.exit(f"ERROR: .BTF section length {len(btf_raw)} smaller than declared hdr_len {btf_hdr_len}")

btf_type_off = int.from_bytes(btf_raw[8:12], "little")
btf_type_len = int.from_bytes(btf_raw[12:16], "little")
btf_str_off = int.from_bytes(btf_raw[16:20], "little")
btf_str_len = int.from_bytes(btf_raw[20:24], "little")

if btf_type_len == 0:
    sys.exit("ERROR: .BTF type_len is 0; type section must not be empty")

str_start = btf_hdr_len + btf_str_off
str_end = str_start + btf_str_len
if str_end > len(btf_raw):
    sys.exit("ERROR: .BTF string table extends beyond .BTF section")
btf_strtab = btf_raw[str_start:str_end]

def get_btf_string(offset):
    if offset >= len(btf_strtab):
        return ""
    return btf_strtab[offset:].split(b"\x00", 1)[0].decode("latin1")

# Parse BTF types table
type_start = btf_hdr_len + btf_type_off
type_end = type_start + btf_type_len
if type_end > len(btf_raw):
    sys.exit("ERROR: .BTF type section extends beyond .BTF section")

type_bytes = btf_raw[type_start:type_end]
btf_types = {}
type_id = 1
t_idx = 0

while t_idx < len(type_bytes):
    if t_idx + 12 > len(type_bytes):
        sys.exit(f"ERROR: .BTF type section has {len(type_bytes) - t_idx} trailing bytes (incomplete binary grammar)")
    name_off = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
    info = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little")
    size_or_type = int.from_bytes(type_bytes[t_idx+8:t_idx+12], "little")
    t_idx += 12

    kind = (info >> 24) & 0x1F
    vlen = info & 0xFFFF
    name = get_btf_string(name_off)

    members = []
    array_info = {}
    int_info = None
    sec_entries = []
    if kind in (4, 5):  # STRUCT, UNION
        if t_idx + vlen * 12 > len(type_bytes):
            sys.exit("ERROR: .BTF struct member truncated")
        for _ in range(vlen):
            m_name_off = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
            m_type = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little")
            m_off = int.from_bytes(type_bytes[t_idx+8:t_idx+12], "little")
            t_idx += 12
            members.append({"name": get_btf_string(m_name_off), "type": m_type, "offset": m_off})
    elif kind == 1:  # INT
        if t_idx + 4 > len(type_bytes):
            sys.exit("ERROR: .BTF int payload truncated")
        int_info = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
        t_idx += 4
    elif kind == 3:  # ARRAY
        if t_idx + 12 > len(type_bytes):
            sys.exit("ERROR: .BTF array record truncated")
        arr_elem_type = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
        arr_idx_type = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little")
        arr_nelems = int.from_bytes(type_bytes[t_idx+8:t_idx+12], "little")
        t_idx += 12
        array_info = {"type": arr_elem_type, "index_type": arr_idx_type, "nelems": arr_nelems}
    elif kind == 6:  # ENUM
        if t_idx + vlen * 8 > len(type_bytes):
            sys.exit("ERROR: .BTF enum member truncated")
        for _ in range(vlen):
            e_name_off = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
            e_val = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little", signed=True)
            t_idx += 8
            members.append({"name": get_btf_string(e_name_off), "val": e_val})
    elif kind in (13,):  # FUNC_PROTO
        if t_idx + vlen * 8 > len(type_bytes):
            sys.exit("ERROR: .BTF func_proto payload truncated")
        t_idx += vlen * 8
    elif kind == 14:  # VAR
        if t_idx + 4 > len(type_bytes):
            sys.exit("ERROR: .BTF var payload truncated")
        t_idx += 4
    elif kind == 15:  # DATASEC
        if t_idx + vlen * 12 > len(type_bytes):
            sys.exit("ERROR: .BTF datasec payload truncated")
        for _ in range(vlen):
            sec_entries.append(tuple(int.from_bytes(type_bytes[t_idx+n:t_idx+n+4], "little") for n in (0, 4, 8)))
            t_idx += 12
        pass
    elif kind == 17:  # DECL_TAG
        if t_idx + 4 > len(type_bytes):
            sys.exit("ERROR: .BTF decl_tag payload truncated")
        t_idx += 4
    elif kind == 19:  # ENUM64
        if t_idx + vlen * 12 > len(type_bytes):
            sys.exit("ERROR: .BTF enum64 member truncated")
        for _ in range(vlen):
            e_name_off = int.from_bytes(type_bytes[t_idx : t_idx + 4], "little")
            e_val_lo = int.from_bytes(type_bytes[t_idx + 4 : t_idx + 8], "little")
            e_val_hi = int.from_bytes(type_bytes[t_idx + 8 : t_idx + 12], "little")
            t_idx += 12
            e_val = (e_val_hi << 32) | e_val_lo
            members.append({"name": get_btf_string(e_name_off), "val": e_val})
    elif kind in (0, 2, 7, 8, 9, 10, 11, 12, 16, 18):
        pass
    else:
        sys.exit(f"ERROR: .BTF unknown type kind {kind}")

    btf_types[type_id] = {"name": name, "kind": kind, "size_or_type": size_or_type, "members": members, "array_info": array_info, "int_info": int_info, "sec_entries": sec_entries}
    type_id += 1

if t_idx != len(type_bytes):
    sys.exit(f"ERROR: .BTF type section has {len(type_bytes) - t_idx} trailing bytes (incomplete binary grammar)")
if not btf_types:
    sys.exit("ERROR: .BTF contains 0 parsed types")

MODIFIER_KINDS = {8, 9, 10, 11, 18}  # TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG

def resolve_type_modifiers(tid, btf_types_map, max_depth=64):
    visited = set()
    curr = tid
    while curr in btf_types_map and btf_types_map[curr]["kind"] in MODIFIER_KINDS and len(visited) < max_depth:
        if curr in visited:
            sys.exit(f"ERROR: Cyclic BTF type modifier detected involving type ID {curr}")
        visited.add(curr)
        curr = btf_types_map[curr]["size_or_type"]
    if len(visited) >= max_depth:
        sys.exit(f"ERROR: Excessive BTF type modifier depth (>= {max_depth}) for type ID {tid}")
    return curr

def type_checked(tid):
    tid = resolve_type_modifiers(tid, btf_types)
    if tid not in btf_types:
        sys.exit(f"ERROR: unresolved E3 BTF type {tid}")
    return btf_types[tid]

def pointer_to(t, kind, name=None):
    if t["kind"] != 2:
        return False
    target = type_checked(t["size_or_type"])
    return target["kind"] == kind and (name is None or target["name"] == name)

def scalar(t, size, signed):
    return (t["kind"] == 1 and t["size_or_type"] == size and
            t["int_info"] is not None and (t["int_info"] & 255) == size * 8 and
            ((t["int_info"] >> 16) & 255) == 0 and
            bool((t["int_info"] >> 24) & 1) == signed)

if profile == "e3":
    datasecs = [t for t in btf_types.values() if t["kind"] == 15 and t["name"] == ".maps"]
    if len(datasecs) != 1:
        sys.exit("ERROR: E3 map DATASEC missing or duplicated")
    entries = {}
    for tid, offset, size in datasecs[0]["sec_entries"]:
        var = type_checked(tid)
        if var["kind"] != 14 or var["name"] in entries or not size or offset + size > len(sections[".maps"]):
            sys.exit("ERROR: invalid E3 map DATASEC entry")
        definition = type_checked(var["size_or_type"])
        if definition["kind"] != 4 or definition["size_or_type"] != size:
            sys.exit("ERROR: E3 map DATASEC size/type mismatch")
        entries[var["name"]] = definition
    if set(entries) != {"e3_state", "e3_events"}:
        sys.exit("ERROR: E3 map DATASEC variables mismatch")
    def map_members(name, expected):
        t = entries[name]
        if t["kind"] != 4:
            sys.exit(f"ERROR: E3 map {name} is not a struct")
        members = {m["name"]: type_checked(m["type"]) for m in t["members"]}
        if set(members) != set(expected):
            sys.exit(f"ERROR: E3 map {name} members mismatch")
        for field, spec in expected.items():
            p = members[field]
            if p["kind"] != 2:
                sys.exit(f"ERROR: E3 map {name}.{field} is not a pointer")
            target = type_checked(p["size_or_type"])
            if isinstance(spec, int):
                if target["kind"] != 3 or target["array_info"].get("nelems") != spec or not scalar(type_checked(target["array_info"]["type"]), 4, True):
                    sys.exit(f"ERROR: E3 map {name}.{field} constant mismatch")
            elif spec == "u32":
                if not scalar(target, 4, False):
                    sys.exit(f"ERROR: E3 map {name}.{field} type mismatch")
            elif target["kind"] != 4 or target["name"] != spec or target["size_or_type"] != 48:
                sys.exit(f"ERROR: E3 map {name}.{field} type mismatch")
            elif spec == "e3_bpf_state":
                expected_fields = ("target_cgroup_id", "attempts", "submitted", "loss", "extraction_errors", "overflow")
                if len(target["members"]) != len(expected_fields):
                    sys.exit("ERROR: E3 state value field count mismatch")
                for index, (field, member) in enumerate(zip(expected_fields, target["members"])):
                    if member["name"] != field or member["offset"] != index * 64 or not scalar(type_checked(member["type"]), 8, False):
                        sys.exit(f"ERROR: E3 state value field mismatch: {field}")
    map_members("e3_state", {"type": 2, "max_entries": 1, "key": "u32", "value": "e3_bpf_state"})
    map_members("e3_events", {"type": 27, "max_entries": 262144})
# --- Parse and Validate .BTF.ext CO-RE Relocation Records ---
if ".BTF.ext" not in sections:
    sys.exit("ERROR: .BTF.ext section missing from BPF object")

btf_ext = sections[".BTF.ext"]
if len(btf_ext) < 32:
    sys.exit("ERROR: .BTF.ext section too short to contain CO-RE header (expected >= 32)")

btf_magic = int.from_bytes(btf_ext[0:2], "little")
if btf_magic != 0xEB9F:
    sys.exit(f"ERROR: .BTF.ext magic mismatch: expected 0xeb9f, got 0x{btf_magic:04x}")

btf_ext_version = btf_ext[2]
if btf_ext_version != 1:
    sys.exit(f"ERROR: .BTF.ext version mismatch: expected 1, got {btf_ext_version}")

hdr_len = int.from_bytes(btf_ext[4:8], "little")
if hdr_len < 32:
    sys.exit(f"ERROR: .BTF.ext header length {hdr_len} too small for CO-RE relocations (expected >= 32)")
if len(btf_ext) < hdr_len:
    sys.exit(f"ERROR: .BTF.ext section length {len(btf_ext)} smaller than declared hdr_len {hdr_len}")

core_relo_off = int.from_bytes(btf_ext[24:28], "little")
core_relo_len = int.from_bytes(btf_ext[28:32], "little")

if core_relo_len == 0:
    sys.exit("ERROR: .BTF.ext core_relo_len is 0; no real CO-RE relocation records present")

start = hdr_len + core_relo_off
end = start + core_relo_len
if end > len(btf_ext):
    sys.exit(f"ERROR: .BTF.ext core_relo bounds exceed section size ({end} > {len(btf_ext)})")

relo_bytes = btf_ext[start:end]
if len(relo_bytes) < 4:
    sys.exit("ERROR: .BTF.ext core_relo data truncated")

rec_size = int.from_bytes(relo_bytes[0:4], "little")
if rec_size != 16:
    sys.exit(f"ERROR: .BTF.ext core_relo record size {rec_size} != expected 16 bytes")

prog_sec_len = len(sections.get("tp_btf/sched_process_exec", b""))
if prog_sec_len == 0:
    sys.exit("ERROR: Target program section 'tp_btf/sched_process_exec' is empty")

relo_idx = 4
total_core_relocs = 0
found_target_section = False
accessors = set()

while relo_idx < len(relo_bytes):
    if relo_idx + 8 > len(relo_bytes):
        sys.exit(f"ERROR: .BTF.ext core_relo has {len(relo_bytes) - relo_idx} trailing bytes (incomplete binary grammar)")
    sec_name_off = int.from_bytes(relo_bytes[relo_idx : relo_idx + 4], "little")
    num_info = int.from_bytes(relo_bytes[relo_idx + 4 : relo_idx + 8], "little")
    relo_idx += 8
    sec_name = get_btf_string(sec_name_off)
    if not sec_name:
        sys.exit(f"ERROR: Invalid sec_name_off {sec_name_off} in .BTF.ext core_relo")

    is_target_sec = (sec_name == "tp_btf/sched_process_exec")
    if is_target_sec:
        found_target_section = True

    if num_info == 0:
        sys.exit(f"ERROR: Section '{sec_name}' has 0 CO-RE relocation records")

    for _ in range(num_info):
        if relo_idx + 16 > len(relo_bytes):
            sys.exit("ERROR: .BTF.ext core_relo record truncated")
        rec = relo_bytes[relo_idx : relo_idx + 16]
        relo_idx += 16

        insn_off = int.from_bytes(rec[0:4], "little")
        type_id = int.from_bytes(rec[4:8], "little")
        access_str_off = int.from_bytes(rec[8:12], "little")
        kind = int.from_bytes(rec[12:16], "little")

        # Reject zeroed or uninitialized records
        if type_id == 0 or access_str_off == 0:
            sys.exit(f"ERROR: Zeroed or invalid CO-RE record detected (type_id={type_id}, access_str_off={access_str_off})")

        # Validate type_id exists in parsed BTF types table
        if type_id not in btf_types:
            sys.exit(f"ERROR: CO-RE relocation references non-existent BTF type ID {type_id} (max {len(btf_types)})")

        # Validate insn_off (multiple of 8 bytes in BPF bytecode, within section)
        if is_target_sec:
            if insn_off % 8 != 0 or insn_off >= prog_sec_len:
                sys.exit(f"ERROR: Invalid insn_off {insn_off} (not 8-byte aligned or >= {prog_sec_len})")

        # Validate access string grammar (colon-separated non-negative integers)
        access_str = get_btf_string(access_str_off)
        if not access_str:
            sys.exit(f"ERROR: Empty access string at offset {access_str_off}")
        access_parts = access_str.split(":")
        if not access_parts or any(not p.isdigit() for p in access_parts):
            sys.exit(f"ERROR: Invalid CO-RE access string grammar: '{access_str}' (must be colon-separated integers)")

        # Validate kind per BPF CO-RE specification
        if kind not in range(0, 13):
            sys.exit(f"ERROR: Disallowed or unknown CO-RE relocation kind: {kind}")

        # Walk type and member graph to prove resolution to genuine required fields / types
        curr_type_id = resolve_type_modifiers(type_id, btf_types)
        root_type_id = curr_type_id
        if btf_types.get(root_type_id, {}).get("kind") == 2:
            root_type_id = resolve_type_modifiers(btf_types[root_type_id]["size_or_type"], btf_types)
        root_name = btf_types.get(root_type_id, {}).get("name", "")
        member_names = []
        resolved_field_name = None

        if curr_type_id not in btf_types:
            sys.exit(f"ERROR: Unresolved root type ID {curr_type_id} in CO-RE access path '{access_str}'")

        if kind in (6, 7, 8, 9, 12):
            # Type-based relocations: access_str MUST be "0" (no member path)
            if access_str != "0":
                sys.exit(f"ERROR: Type-based CO-RE relocation (kind {kind}) must have access string '0', got '{access_str}'")
            resolved_field_name = btf_types[curr_type_id].get("name") or f"type_{curr_type_id}"
        elif kind in (10, 11):
            # Enum value relocations: access_str must be single integer index
            if len(access_parts) != 1:
                sys.exit(f"ERROR: Enum value CO-RE relocation (kind {kind}) access string must be single integer, got '{access_str}'")
            enum_idx = int(access_parts[0])
            if btf_types[curr_type_id]["kind"] not in (6, 19):
                sys.exit(f"ERROR: Enum value relocation (kind {kind}) references non-enum type ID {curr_type_id} (kind {btf_types[curr_type_id]['kind']})")
            enum_members = btf_types[curr_type_id].get("members", [])
            if enum_idx >= len(enum_members):
                sys.exit(f"ERROR: Enum value index {enum_idx} out of range (count {len(enum_members)}) in '{access_str}'")
            resolved_field_name = enum_members[enum_idx]["name"]
        else:
            # Field-based relocations (kinds 0..5)
            # If root type is PTR, dereference pointer to pointee
            if btf_types[curr_type_id]["kind"] == 2:  # PTR
                curr_type_id = resolve_type_modifiers(btf_types[curr_type_id]["size_or_type"], btf_types)
                if curr_type_id not in btf_types:
                    sys.exit(f"ERROR: Unresolved pointee type ID {curr_type_id} in CO-RE access path '{access_str}'")

            field_indices = access_parts[1:] if len(access_parts) > 1 else []
            if not field_indices:
                # Whole object field access: resolve to type name
                resolved_field_name = btf_types[curr_type_id].get("name", f"type_{curr_type_id}")
            else:
                for idx_str in field_indices:
                    member_idx = int(idx_str)
                    curr_type_id = resolve_type_modifiers(curr_type_id, btf_types)
                    if curr_type_id not in btf_types:
                        sys.exit(f"ERROR: Unresolved type ID {curr_type_id} in CO-RE member walk '{access_str}'")

                    t_def = btf_types[curr_type_id]
                    if t_def["kind"] in (4, 5):  # STRUCT, UNION
                        members = t_def.get("members", [])
                        if member_idx >= len(members):
                            sys.exit(f"ERROR: Member index {member_idx} out of range for '{t_def['name']}' (len {len(members)}) in '{access_str}'")
                        target_member = members[member_idx]
                        resolved_field_name = target_member["name"]
                        member_names.append(target_member["name"])
                        curr_type_id = resolve_type_modifiers(target_member["type"], btf_types)
                    elif t_def["kind"] == 3:  # ARRAY
                        arr_info = t_def.get("array_info", {})
                        arr_nelems = arr_info.get("nelems", 0)
                        if member_idx >= arr_nelems:
                            sys.exit(f"ERROR: Array index {member_idx} out of bounds (nelems {arr_nelems}) in CO-RE access path '{access_str}'")
                        resolved_field_name = f"[{member_idx}]"
                        curr_type_id = resolve_type_modifiers(arr_info.get("type", 0), btf_types)
                    elif t_def["kind"] == 2:  # PTR
                        resolved_field_name = f"*{t_def.get('name', 'ptr')}"
                        curr_type_id = resolve_type_modifiers(t_def.get("size_or_type", 0), btf_types)
                    else:
                        sys.exit(f"ERROR: Access path index on non-composite type '{t_def['name']}' (kind {t_def['kind']}) in '{access_str}'")

        if not resolved_field_name:
            sys.exit(f"ERROR: Failed to resolve field name for access path '{access_str}'")
        if is_target_sec:
            if profile == "e3":
                key = (root_name, ".".join(member_names), kind)
                scalar_specs = {
                    ("task_struct", "pid"): (4, True), ("task_struct", "tgid"): (4, True),
                    ("task_struct", "start_boottime"): (8, False),
                    ("pid", "level"): (4, False), ("pid_namespace", "ns.inum"): (4, False),
                    ("mnt_namespace", "ns.inum"): (4, False), ("inode", "i_ino"): (8, False),
                    ("inode", "i_size"): (8, True), ("inode", "i_mode"): (2, False),
                    ("super_block", "s_dev"): (4, False), ("mount", "mnt_id"): (4, True),
                }
                pointer_specs = {
                    ("task_struct", "thread_pid"): "pid", ("task_struct", "nsproxy"): "nsproxy",
                    ("task_struct", "mm"): "mm_struct", ("upid", "ns"): "pid_namespace",
                    ("nsproxy", "mnt_ns"): "mnt_namespace", ("linux_binprm", "file"): "file",
                    ("mm_struct", "exe_file"): "file", ("file", "f_inode"): "inode",
                    ("file", "f_path.mnt"): "vfsmount", ("inode", "i_sb"): "super_block",
                }
                terminal = type_checked(curr_type_id)
                pair = key[:2]
                if kind == 0 and member_names:
                    if pair in scalar_specs and not scalar(terminal, *scalar_specs[pair]):
                        sys.exit(f"ERROR: E3 accessor scalar type mismatch: {pair}")
                    if pair in pointer_specs and not pointer_to(terminal, 4, pointer_specs[pair]):
                        sys.exit(f"ERROR: E3 accessor pointer type mismatch: {pair}")
                    if pair == ("pid", "numbers"):
                        arr = terminal["array_info"]
                        if terminal["kind"] != 3 or arr.get("nelems") != 1 or type_checked(arr.get("type", 0))["name"] != "upid" or type_checked(arr["type"])["kind"] != 4:
                            sys.exit("ERROR: E3 pid.numbers array type mismatch")
                    if pair == ("mount", "mnt") and (terminal["kind"] != 4 or terminal["name"] != "vfsmount"):
                        sys.exit("ERROR: E3 mount.mnt type mismatch")
                    accessors.add(key)
                elif kind == 9:
                    if root_name == "upid" and terminal["kind"] != 4:
                        sys.exit("ERROR: E3 upid type size target mismatch")
                    accessors.add((root_name, "", kind))
            total_core_relocs += 1
if relo_idx != len(relo_bytes):
    sys.exit(f"ERROR: .BTF.ext core_relo has {len(relo_bytes) - relo_idx} trailing bytes (incomplete binary grammar)")
if not found_target_section:
    sys.exit("ERROR: .BTF.ext lacks relocations for 'tp_btf/sched_process_exec'")

if total_core_relocs < 10:
    sys.exit(f"ERROR: Expected >= 10 genuine CO-RE relocations for tp_btf/sched_process_exec, found {total_core_relocs}")
if profile == "e3":
    required = {
        ("task_struct", field, 0) for field in
        ("pid", "tgid", "start_boottime", "thread_pid", "nsproxy", "mm")
    } | {
        ("pid", "level", 0), ("pid", "numbers", 0), ("upid", "", 9),
        ("upid", "ns", 0), ("pid_namespace", "ns.inum", 0),
        ("nsproxy", "mnt_ns", 0), ("mnt_namespace", "ns.inum", 0),
        ("linux_binprm", "file", 0), ("mm_struct", "exe_file", 0),
        ("file", "f_inode", 0), ("file", "f_path.mnt", 0),
        ("inode", "i_ino", 0), ("inode", "i_size", 0),
        ("inode", "i_mode", 0), ("inode", "i_sb", 0),
        ("super_block", "s_dev", 0), ("mount", "mnt", 0),
        ("mount", "mnt_id", 0),
    }
    if required - accessors:
        sys.exit(f"ERROR: E3 required CO-RE accessors missing: {sorted(required - accessors)}")
    print("Validated E3 CO-RE accessors:", sorted(accessors))

print(f"Verified genuine .BTF.ext CO-RE relocations: {total_core_relocs} valid records ({core_relo_len} bytes) for tp_btf/sched_process_exec.")

# Header dependency check from .d file
allowed_prefixes = [
    str(pathlib.Path(clang_res).resolve()),
    "/usr/include/x86_64-linux-gnu",
    "/usr/include",
    str(prefix_path),
    str(repo_path),
]

if not os.path.exists(bpf_dep) or os.path.getsize(bpf_dep) == 0:
    sys.exit("ERROR: BPF dependency file missing or empty")

def parse_make_depfile(dep_text):
    colon_idx = dep_text.find(":")
    if colon_idx != -1:
        dep_text = dep_text[colon_idx + 1:]
    tokens = []
    curr_token = []
    i = 0
    n = len(dep_text)
    while i < n:
        c = dep_text[i]
        if c == "\\":
            if i + 1 >= n:
                sys.exit("ERROR: Dangling escape backslash at end of make dependency file")
            next_c = dep_text[i + 1]
            if next_c == "\n":
                i += 2
                continue
            elif next_c == "\r" and i + 2 < n and dep_text[i + 2] == "\n":
                i += 3
                continue
            elif next_c in (" ", "\\", "#", ":"):
                curr_token.append(next_c)
                i += 2
                continue
            elif next_c == "$":
                curr_token.append("$")
                i += 2
                continue
            else:
                curr_token.append(c)
                i += 1
                continue
        elif c == "$":
            if i + 1 < n and dep_text[i + 1] == "$":
                curr_token.append("$")
                i += 2
                continue
            else:
                sys.exit("ERROR: Dangling or unescaped dollar sign in make dependency file")
        elif c.isspace():
            if curr_token:
                tokens.append("".join(curr_token))
                curr_token = []
            i += 1
        else:
            curr_token.append(c)
            i += 1
    if curr_token:
        tokens.append("".join(curr_token))
    return tokens

bpf_compiled_headers = {}
with open(bpf_dep, "r", encoding="utf-8") as f:
    dep_paths = parse_make_depfile(f.read())

if not dep_paths:
    sys.exit("ERROR: BPF dependency file contains no prerequisites (target-only)")

expected_bpf_source = (repo_path / "proof" / ("e3_bpf_exec.bpf.c" if profile == "e3" else "bpf_canary.bpf.c")).resolve()
resolved_bpf_dep_paths = [pathlib.Path(tok).resolve() for tok in dep_paths]
if expected_bpf_source not in resolved_bpf_dep_paths:
    sys.exit(f"ERROR: BPF object dependency graph missing primary source {expected_bpf_source.name}")
for tok in dep_paths:
    p = pathlib.Path(tok).resolve()
    p_str = str(p)
    if not any(p.is_relative_to(pathlib.Path(allowed)) for allowed in allowed_prefixes):
        sys.exit(f"ERROR: BPF object included unapproved header dependency: '{tok}'")
    if profile == "e3" and p.is_relative_to(repo_path) and p not in {
        (repo_path / "proof" / name).resolve()
        for name in ("e3_bpf_exec.bpf.c", "e3_bpf_types.h", "e3_bpf_kernel_types.h")
    }:
        sys.exit(f"ERROR: E3 BPF dependency outside closed source list: '{tok}'")
    if not p.is_file():
        sys.exit(f"ERROR: BPF dependency '{p_str}' missing on disk")
    hdr_bytes = p.read_bytes()
    actual_hdr_sha = hashlib.sha256(hdr_bytes).hexdigest()
    bpf_compiled_headers[p_str] = {
        "sha256": actual_hdr_sha,
        "size": len(hdr_bytes)
    }
    if p.is_relative_to(prefix_path):
        rel_hdr = str(p.relative_to(prefix_path))
        if rel_hdr not in all_locked_headers:
            sys.exit(f"ERROR: BPF object included unapproved header from staged prefix: '{rel_hdr}'")
        expected_hdr_info = all_locked_headers[rel_hdr]
        if "sha256" in expected_hdr_info and actual_hdr_sha.lower() != expected_hdr_info["sha256"].lower():
            sys.exit(f"ERROR: BPF object included header '{rel_hdr}' whose SHA256 does not match lock")
if len(sys.argv) > 8 and sys.argv[8]:
    (pathlib.Path(sys.argv[8]) / "bpf-compiled-headers.json").write_text(
        json.dumps(bpf_compiled_headers, indent=2)
    )
PY
}

validate_host_elf_main() {
  python3 -I - <<'PY' "$@"
import hashlib, json, os, pathlib, subprocess, sys

readelf_bin = sys.argv[1]
host_bin = sys.argv[2]
host_dep = sys.argv[3]
clang_res = sys.argv[4]
prefix = sys.argv[5]
repo_root = sys.argv[6]
owned_dir = sys.argv[7]
lock_file = sys.argv[8]
profile = sys.argv[9] if len(sys.argv) > 9 else "canary"
if profile not in ("canary", "e3_bpf_host", "e3_bpf_validate", "e3_bpf_test", "e3_bpf_test_pure"):
    sys.exit("ERROR: unknown host validation profile")

prefix_path = pathlib.Path(prefix).resolve()
repo_path = pathlib.Path(repo_root).resolve()

with open(lock_file, "r", encoding="utf-8") as f:
    lock = json.load(f)

all_locked_headers = {}
for pkg_name, pkg_data in lock.get("packages", {}).items():
    for hdr in pkg_data.get("required_headers", []):
        if isinstance(hdr, dict):
            all_locked_headers[hdr["path"]] = hdr
        else:
            all_locked_headers[hdr] = {"path": hdr}

def run_readelf(*args):
    cmd = [readelf_bin] + list(args)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        sys.exit(f"ERROR: readelf command failed: {' '.join(cmd)}\n{res.stderr}")
    return res.stdout

# --- Validate Native Host Helper ---
host_hdr = run_readelf("-hW", host_bin)
if "ELF64" not in host_hdr:
    sys.exit("ERROR: Host helper is not ELF64")
if "X86-64" not in host_hdr and "x86-64" not in host_hdr:
    sys.exit("ERROR: Host helper machine is not x86-64")

host_dyn = run_readelf("-dW", host_bin)
needed_libs = set()
for line in host_dyn.splitlines():
    if "(NEEDED)" in line and "Shared library:" in line:
        if "[" in line and "]" in line:
            lib = line.split("[")[1].split("]")[0].strip()
            needed_libs.add(lib)
        else:
            sys.exit(f"ERROR: Malformed NEEDED entry in host helper: {line}")
    if "RPATH" in line or "RUNPATH" in line:
        sys.exit(f"ERROR: Disallowed RPATH/RUNPATH found in host helper: {line.strip()}")

# Expected DT_NEEDED set: libc.so.6 only (exact set equality, no substrings or additions)
if needed_libs != {"libc.so.6"}:
    sys.exit(f"ERROR: Disallowed dynamic dependencies in host helper: {needed_libs}; expected exactly {{'libc.so.6'}}")

# Validate program headers directly from binary and readelf
with open(host_bin, "rb") as f:
    host_raw = f.read()

if len(host_raw) < 64 or host_raw[:4] != b"\x7fELF":
    sys.exit("ERROR: Host helper is not a valid ELF file")

e_phoff = int.from_bytes(host_raw[32:40], "little")
e_phentsize = int.from_bytes(host_raw[54:56], "little")
e_phnum = int.from_bytes(host_raw[56:58], "little")

PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1

has_gnu_stack = False
interp_path = None

for i in range(e_phnum):
    ph = host_raw[e_phoff + i * e_phentsize : e_phoff + (i + 1) * e_phentsize]
    p_type = int.from_bytes(ph[0:4], "little")
    p_flags = int.from_bytes(ph[4:8], "little")
    p_offset = int.from_bytes(ph[8:16], "little")
    p_filesz = int.from_bytes(ph[32:40], "little")

    if p_type == PT_INTERP:
        interp_bytes = host_raw[p_offset : p_offset + p_filesz]
        interp_path = interp_bytes.split(b"\x00", 1)[0].decode("latin1")

    if p_type == PT_GNU_STACK:
        has_gnu_stack = True
        if p_flags & PF_X != 0:
            sys.exit(f"ERROR: Host helper has EXECUTABLE STACK (PT_GNU_STACK p_flags=0x{p_flags:x})")

if not has_gnu_stack:
    sys.exit("ERROR: Host helper missing PT_GNU_STACK program header")

if interp_path != "/lib64/ld-linux-x86-64.so.2":
    sys.exit(f"ERROR: Host helper interpreter mismatch: expected '/lib64/ld-linux-x86-64.so.2', got '{interp_path}'")

# Also verify readelf -lW output parsing correctly (Flg is parts[-2], Align is parts[-1])
host_prog = run_readelf("-lW", host_bin)
found_gnu_stack_line = False
for line in host_prog.splitlines():
    parts = line.split()
    if len(parts) >= 7 and parts[0] == "GNU_STACK":
        found_gnu_stack_line = True
        flg = parts[-2]
        if "E" in flg or "X" in flg:
            sys.exit(f"ERROR: Host helper has executable stack (GNU_STACK flag is '{flg}')")

if not found_gnu_stack_line:
    sys.exit("ERROR: GNU_STACK segment missing in readelf -lW output")

# Check that dependency functions are statically defined in binary (not UND)
host_sym = run_readelf("-sW", host_bin)
required_symbols = [] if profile == "e3_bpf_test_pure" else ["bpf_object__open_file", "bpf_object__load", "elf_begin", "deflate", "ZSTD_decompress"]
if profile not in ("canary", "e3_bpf_test_pure"):
    required_symbols += ["e3_bpf_observer_open", "e3_bpf_observer_finish",
                         "e3_bpf_observer_close", "e3_bpf_capture_record",
                         "e3_bpf_capture_finish"]
elif profile == "e3_bpf_test_pure":
    required_symbols += ["e3_bpf_capture_record", "e3_bpf_capture_finish"]
for sym in required_symbols:
    found = False
    for line in host_sym.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[7] == sym:
            if parts[6] != "UND":
                found = True
                break
    if not found:
        sys.exit(f"ERROR: Required static dependency symbol '{sym}' is not defined in host helper")

# Validate host .d dependency graph
allowed_prefixes = [
    str(pathlib.Path(clang_res).resolve()),
    "/usr/include/x86_64-linux-gnu",
    "/usr/include",
    str(prefix_path),
    str(repo_path),
]

# Load bpf-compiled-headers.json (must exist, be non-empty, valid JSON dict with > 0 records including primary BPF source)
bpf_headers_file = pathlib.Path(owned_dir) / "bpf-compiled-headers.json"
if not bpf_headers_file.is_file() or os.path.getsize(bpf_headers_file) == 0:
    sys.exit("ERROR: Missing or empty BPF compiled headers record; cannot merge dual dependency graphs")

try:
    bpf_compiled = json.loads(bpf_headers_file.read_text(encoding="utf-8"))
except Exception as e:
    sys.exit(f"ERROR: Malformed BPF compiled headers record: {e}; cannot merge dual dependency graphs")

if not isinstance(bpf_compiled, dict) or len(bpf_compiled) == 0:
    sys.exit("ERROR: BPF compiled headers record contains 0 records; cannot merge dual dependency graphs")

expected_bpf_source_str = str((repo_path / "proof" / ("bpf_canary.bpf.c" if profile == "canary" else "e3_bpf_exec.bpf.c")).resolve())
if expected_bpf_source_str not in bpf_compiled:
    sys.exit(f"ERROR: BPF compiled headers record missing primary source '{expected_bpf_source_str}'")

compiled_source_header_digests = {**bpf_compiled}
if not os.path.exists(host_dep) or os.path.getsize(host_dep) == 0:
    sys.exit("ERROR: Host helper dependency file missing or empty")

def parse_make_depfile(dep_text):
    colon_idx = dep_text.find(":")
    if colon_idx != -1:
        dep_text = dep_text[colon_idx + 1:]
    tokens = []
    curr_token = []
    i = 0
    n = len(dep_text)
    while i < n:
        c = dep_text[i]
        if c == "\\":
            if i + 1 >= n:
                sys.exit("ERROR: Dangling escape backslash at end of make dependency file")
            next_c = dep_text[i + 1]
            if next_c == "\n":
                i += 2
                continue
            elif next_c == "\r" and i + 2 < n and dep_text[i + 2] == "\n":
                i += 3
                continue
            elif next_c in (" ", "\\", "#", ":"):
                curr_token.append(next_c)
                i += 2
                continue
            elif next_c == "$":
                curr_token.append("$")
                i += 2
                continue
            else:
                curr_token.append(c)
                i += 1
                continue
        elif c == "$":
            if i + 1 < n and dep_text[i + 1] == "$":
                curr_token.append("$")
                i += 2
                continue
            else:
                sys.exit("ERROR: Dangling or unescaped dollar sign in make dependency file")
        elif c.isspace():
            if curr_token:
                tokens.append("".join(curr_token))
                curr_token = []
            i += 1
        else:
            curr_token.append(c)
            i += 1
    if curr_token:
        tokens.append("".join(curr_token))
    return tokens

with open(host_dep, "r", encoding="utf-8") as f:
    host_dep_paths = parse_make_depfile(f.read())
if not host_dep_paths:
    sys.exit("ERROR: Host helper dependency file contains no prerequisites (target-only)")

source_profile = "e3_bpf_test" if profile == "e3_bpf_test_pure" else profile
expected_host_source = (repo_path / "proof" / ("bpf_canary_host.c" if profile == "canary" else source_profile + ".c")).resolve()
resolved_host_dep_paths = [pathlib.Path(tok).resolve() for tok in host_dep_paths]
if expected_host_source not in resolved_host_dep_paths:
    sys.exit(f"ERROR: Host helper dependency graph missing primary source {expected_host_source.name}")

gcc_gate = None
gcc_baseline = None
for tok in host_dep_paths:
    lexical = pathlib.Path(tok)
    p = lexical.resolve()
    p_str = str(p)
    gcc_root = pathlib.Path("/usr/lib/gcc/x86_64-linux-gnu/13/include")
    gcc_entry = None
    if lexical.is_absolute() and lexical.is_relative_to(gcc_root):
        if gcc_gate is None:
            import importlib.util
            spec = importlib.util.spec_from_file_location("bpf_runner_baseline", repo_path / "proof/bpf_runner_baseline.py")
            if spec is None or spec.loader is None:
                sys.exit("ERROR: GCC baseline verifier unavailable")
            gcc_gate = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gcc_gate)
            gcc_baseline = gcc_gate.load_gcc_baseline()
        try:
            gcc_entry = gcc_gate.check_gcc_dependency(tok, gcc_baseline)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            sys.exit(f"ERROR: GCC dependency verification failed: {exc}")
    elif p.is_relative_to(gcc_root):
        sys.exit(f"ERROR: Unrecorded alias for GCC dependency: '{tok}'")
    elif not any(p.is_relative_to(pathlib.Path(allowed)) for allowed in allowed_prefixes):
        sys.exit(f"ERROR: Host helper included unapproved dependency from untrusted path: '{tok}'")
    if profile != "canary" and p.is_relative_to(repo_path) and p not in {
        (repo_path / "proof" / name).resolve()
        for name in (source_profile + ".c", "e3_bpf_host.h", "e3_bpf_types.h")
    }:
        sys.exit(f"ERROR: E3 native dependency outside closed source list: '{tok}'")
    if not p.is_file():
        sys.exit(f"ERROR: Host dependency '{p_str}' missing on disk")
    hdr_bytes = p.read_bytes()
    actual_hdr_sha = hashlib.sha256(hdr_bytes).hexdigest()
    if gcc_entry is not None and (len(hdr_bytes) != gcc_entry["size"] or actual_hdr_sha != gcc_entry["sha256"]):
        sys.exit(f"ERROR: GCC dependency changed while recording: '{tok}'")
    compiled_source_header_digests[p_str] = {
        "sha256": actual_hdr_sha,
        "size": len(hdr_bytes)
    }
    if p.is_relative_to(prefix_path):
        rel_hdr = str(p.relative_to(prefix_path))
        if rel_hdr not in all_locked_headers:
            sys.exit(f"ERROR: Host helper included unapproved header from staged prefix: '{rel_hdr}'")
        expected_hdr_info = all_locked_headers[rel_hdr]
        if "sha256" in expected_hdr_info and actual_hdr_sha.lower() != expected_hdr_info["sha256"].lower():
            sys.exit(f"ERROR: Host helper included header '{rel_hdr}' whose SHA256 does not match lock")
(pathlib.Path(owned_dir) / "compiled-headers.json").write_text(
    json.dumps(compiled_source_header_digests, indent=2)
)
print("Validated Host helper binary and dependency graph successfully.")
PY
}

evaluate_report_main() {
  python3 -I - <<'PY' "$@"
import json, os, pathlib, sys

status_file = sys.argv[1]
with open(status_file, "r", encoding="utf-8") as f:
    r = json.load(f)

p = r.get("observed_kernel_prog") or {}
l = r.get("observed_kernel_link") or {}
caps = r.get("capabilities") or {}
proc = r.get("process_identity") or {}
memlock = r.get("memlock") or {}
verifier = r.get("verifier_evidence") or {}
relo = r.get("relocation_evidence") or {}

ok = (
    r.get("status") == "PROBE_SUCCESS"
    and r.get("strict_eligible") is False
    and r.get("exec_identity_tested") is False
    and r.get("bpf_load_supported") is True
    and r.get("bpf_attach_supported") is True
    and r.get("hook_identity_verified") is True
    and r.get("link_association_verified") is True
    and r.get("fd_ownership_lifecycle") == "detached_and_closed_before_report"
    and p.get("prog_type") == 26
    and isinstance(p.get("prog_id"), int) and p["prog_id"] > 0
    and isinstance(p.get("attach_btf_id"), int) and p["attach_btf_id"] > 0
    and l.get("link_type") == 1
    and l.get("link_prog_id") == p["prog_id"]
    and l.get("link_tp_name") == "sched_process_exec"
    and l.get("target_hook_name") == "btf_trace_sched_process_exec"
    and l.get("target_hook_kind") == "BTF_KIND_TYPEDEF"
    and caps.get("cap_bpf") is True
    and caps.get("cap_perfmon") is True
    and caps.get("cap_sys_admin") is False
    and caps.get("all_other_caps_clear") is True
    and proc.get("uid", 0) != 0
    and proc.get("gid", 0) != 0
    and memlock.get("automatic_rlim_disabled") is True
    and verifier.get("log_valid") is True
    and relo.get("core_relocation_retained") is True
)

if not ok:
    sys.exit(f"BPF terminal report is incomplete or inconsistent:\n{json.dumps(r, indent=2)}")

# Verify actual nontruncated log files on disk
vlog_path = verifier.get("log_file")
if not vlog_path or not os.path.isfile(vlog_path):
    sys.exit(f"ERROR: Verifier log file '{vlog_path}' missing on disk")
vlog_size = os.path.getsize(vlog_path)
expected_vlog_bytes = verifier.get("log_bytes", 0)
if vlog_size != expected_vlog_bytes or vlog_size == 0:
    sys.exit(f"ERROR: Verifier log file size mismatch/truncated: {vlog_size} != {expected_vlog_bytes}")
with open(vlog_path, "r", encoding="utf-8") as vf:
    vlog_text = vf.read()
if "processed " not in vlog_text:
    sys.exit("ERROR: Verifier log file missing verifier conclusion ('processed ')")

llog_path = relo.get("log_file")
if not llog_path or not os.path.isfile(llog_path):
    sys.exit(f"ERROR: Libbpf debug log file '{llog_path}' missing on disk")
llog_size = os.path.getsize(llog_path)
expected_llog_bytes = relo.get("libbpf_debug_log_bytes", 0)
if llog_size != expected_llog_bytes or llog_size == 0:
    sys.exit(f"ERROR: Libbpf debug log file size mismatch/truncated: {llog_size} != {expected_llog_bytes}")
with open(llog_path, "r", encoding="utf-8") as lf:
    llog_text = lf.read()
if not any(token in llog_text for token in ["relo #", "bpf_core_relo", "CO-RE"]):
    sys.exit("ERROR: Libbpf debug log file missing genuine CO-RE relocation diagnostics")

print("BPF terminal diagnostic feasibility report verified successfully (including verified verifier and libbpf logs on disk).")
PY
}

validate_build_integrity_main() {
  python3 -I - <<'PY' "$@"
import hashlib, json, pathlib, sys
owned = pathlib.Path(sys.argv[1])
outputs = {"bpf_obj": pathlib.Path(sys.argv[2]), "host_bin": pathlib.Path(sys.argv[3])}
headers = json.loads((owned / "compiled-headers.json").read_text(encoding="utf-8"))
if not isinstance(headers, dict) or not headers:
    sys.exit("ERROR: compiled header record missing or empty")
for name, expected in headers.items():
    path = pathlib.Path(name)
    if not path.is_file():
        sys.exit(f"ERROR: Compiled header/source '{name}' missing before launch")
    data = path.read_bytes()
    if len(data) != expected["size"] or hashlib.sha256(data).hexdigest().lower() != expected["sha256"].lower():
        sys.exit(f"ERROR: Header/source tampering detected before capability launch for '{name}'")
record = json.loads((owned / "diagnostic-build-record.json").read_text(encoding="utf-8"))
for name, path in outputs.items():
    expected = record["outputs"][name]
    if str(path) != expected["path"] or not path.is_file():
        sys.exit(f"ERROR: Output path missing or mismatched: {name}")
    if hashlib.sha256(path.read_bytes()).hexdigest().lower() != expected["sha256"].lower():
        sys.exit(f"ERROR: Output tampering detected before capability launch: {name}")
print("Build integrity verified: headers, sources, and outputs unchanged.")
PY
}


# Check for sub-actions invoked for direct testing
if [ $# -gt 0 ]; then
  case "$1" in
    --validate-build-integrity)
      shift
      validate_build_integrity_main "$@"
      exit 0
      ;;
    --validate-bpf-obj)
      shift
      validate_bpf_obj_main "$@"
      exit 0
      ;;
    --validate-host-elf)
      shift
      validate_host_elf_main "$@"
      exit 0
      ;;
    --evaluate-report)
      shift
      evaluate_report_main "$@"
      exit 0
      ;;
    --validate-staged-manifest)
      shift
      validate_staged_manifest_main "$@"
      exit 0
      ;;
  esac
fi

# --- Main Driver CLI Option Parsing ---

LOCK_FILE="$DEFAULT_LOCK_FILE"
OWNED_DIR=""
STATUS_FILE=""
BUILD_ONLY=0
E3_BUILD_ONLY=0
VERBOSE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --lock|--dependency-script|--prefix|--receipt)
      echo "ERROR: Option '$1' is forbidden; exact approved repository lock and consumer are pinned" >&2
      exit 1
      ;;
    --owned-dir)
      OWNED_DIR="$2"
      shift 2
      ;;
    --status)
      STATUS_FILE="$2"
      shift 2
      ;;
    --build-only|--skip-launch)
      BUILD_ONLY=1
      shift
      ;;
    --e3-build-only)
      E3_BUILD_ONLY=1
      shift
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option '$1'" >&2
      usage >&2
      exit 1
      ;;
  esac
done
if [ "$E3_BUILD_ONLY" -eq 1 ]; then
  for rel in proof/run_bpf_feasibility.sh proof/bpf_dependencies.py \
      proof/bpf_dependencies.lock.json proof/bpf_runner_baseline.py proof/bpf_baseline_process.py \
      proof/bpf_tool_baseline.json proof/bpf_gcc_include_baseline.json \
      proof/test_bpf_dependencies.py proof/test_bpf_runner_baseline.py \
      proof/test_bpf_build_script.py \
      .github/workflows/pr147-e3-bpf-build.yml; do
    if ! /usr/bin/git -C "$REPO_ROOT" cat-file -e "HEAD:$rel" ||
       ! /usr/bin/git -C "$REPO_ROOT" diff --quiet HEAD -- "$rel"; then
      echo "ERROR: E3 recipe input differs from checkout: $rel" >&2
      exit 1
    fi
  done
fi
# Set up fresh, exclusive owned private scratch directory with umask 077 (no mkdir -p reuse, no symlinks)
if [ -n "${RUNNER_TEMP:-}" ]; then
  if [ -L "$RUNNER_TEMP" ]; then
    echo "ERROR: RUNNER_TEMP is a symlink: $RUNNER_TEMP" >&2
    exit 1
  fi
  BASE_TEMP="$RUNNER_TEMP"
else
  BASE_TEMP="${TMPDIR:-/tmp}"
fi

OLD_UMASK="$(umask)"
umask 077
if [ -z "$OWNED_DIR" ]; then
  OWNED_DIR="$(mktemp -d "$BASE_TEMP/bpf-feasibility.XXXXXX")"
else
  if [ -e "$OWNED_DIR" ] || [ -L "$OWNED_DIR" ]; then
    echo "ERROR: OWNED_DIR '$OWNED_DIR' already exists or is a symlink; fresh exclusive directory required" >&2
    exit 1
  fi
  mkdir -m 0700 "$OWNED_DIR"
fi
umask "$OLD_UMASK"

if [ -L "$OWNED_DIR" ]; then
  echo "ERROR: Owned scratch directory is a symlink: $OWNED_DIR" >&2
  exit 1
fi

mkdir -m 0700 "$OWNED_DIR/tmp"

if [ ! -f "$LOCK_FILE" ]; then
  echo "ERROR: Dependency lock '$LOCK_FILE' not found" >&2
  exit 1
fi
if [ ! -f "$DEP_SCRIPT" ]; then
  echo "ERROR: Dependency script '$DEP_SCRIPT' not found" >&2
  exit 1
fi


if [ -z "$STATUS_FILE" ]; then
  STATUS_FILE="$OWNED_DIR/bpf-feasibility.json"
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Repository root: $REPO_ROOT"
  echo "[run_bpf_feasibility] Scratch working directory: $OWNED_DIR"
fi
# Validate the independently preserved runner census before invoking its tools.
python3 -I "$REPO_ROOT/proof/bpf_runner_baseline.py"


# 1. Dependency staging and verification via shared contract
STAGED_PREFIX="$OWNED_DIR/staged-prefix"
RECEIPT_FILE="$OWNED_DIR/bpf-dependency-receipt.json"

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Invoking authenticated dependency consumer: python3 -I $DEP_SCRIPT --lock $LOCK_FILE --output $STAGED_PREFIX --receipt $RECEIPT_FILE"
fi

python3 -I "$DEP_SCRIPT" --lock "$LOCK_FILE" --output "$STAGED_PREFIX" --receipt "$RECEIPT_FILE"

# Authoritative pre-compilation manifest validation
validate_staged_manifest_main "$LOCK_FILE" "$RECEIPT_FILE" "$STAGED_PREFIX"

# The baseline verifier pins the exact compiler, tool and resource identities.
CLANG_BIN="/usr/bin/clang-18"
CLANG_RESOURCE="/usr/lib/llvm-18/lib/clang/18"
GCC_BIN="/usr/bin/gcc-13"
READELF_BIN="/usr/bin/readelf"

# Recheck the same version-controlled baseline immediately before compilation.
python3 -I "$REPO_ROOT/proof/bpf_runner_baseline.py"

if [ "$E3_BUILD_ONLY" -eq 1 ]; then
  # This profile has a closed source list and exits before the capability path.
  # The caller retains stdout/stderr even if a command fails.
  python3 -I - "$REPO_ROOT" "$OWNED_DIR" <<'PY'
import hashlib, json, pathlib, subprocess, sys
root, out = map(pathlib.Path, sys.argv[1:])
subject = "be6d754aa7f7be709273281ff10fc0a0b68db8e6"
files = ["e3_bpf_types.h", "e3_bpf_kernel_types.h", "e3_bpf_exec.bpf.c",
         "e3_bpf_host.h", "e3_bpf_host.c", "e3_bpf_validate.c", "e3_bpf_test.c"]
def git(*args):
    return subprocess.run(["/usr/bin/git", "-C", str(root), *args],
                          check=True, stdout=subprocess.PIPE).stdout
revision = git("rev-parse", "HEAD").decode().strip()
digests = {}
for name in files:
    rel = "proof/" + name
    data = (root / rel).read_bytes()
    if data != git("show", f"{subject}:{rel}"):
        sys.exit(f"ERROR: E3 subject differs from {subject}: {rel}")
    digests[rel] = hashlib.sha256(data).hexdigest()
for rel in ("proof/run_bpf_feasibility.sh", ".github/workflows/pr147-e3-bpf-build.yml"):
    if (root / rel).read_bytes() != git("show", f"{revision}:{rel}"):
        sys.exit(f"ERROR: build recipe differs from checkout: {rel}")
record = {"witness_source_sha": subject, "build_recipe_sha": revision,
          "source_sha256": digests, "strict_eligible": False,
          "load_attempted": False, "attach_attempted": False,
          "exec_identity_tested": False}
(out / "e3-subject.json").write_text(json.dumps(record, indent=2) + "\n")
PY
  for unit in e3_bpf_validate e3_bpf_test e3_bpf_host; do
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$OWNED_DIR/tmp" \
      "$GCC_BIN" -O2 -g -Wall -Wextra -Werror=implicit-function-declaration \
      -UNDEBUG -fPIE -I"$STAGED_PREFIX/usr/include" -I"$REPO_ROOT/proof" \
      -MD -MF "$OWNED_DIR/$unit.d" -c "$REPO_ROOT/proof/$unit.c" \
      -o "$OWNED_DIR/$unit.o"
  done
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$GCC_BIN" -pie \
    "$OWNED_DIR/e3_bpf_test.o" "$OWNED_DIR/e3_bpf_validate.o" \
    -Wl,-z,relro,-z,now,-z,noexecstack -o "$OWNED_DIR/e3_bpf_test"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C "$GCC_BIN" -pie \
    "$OWNED_DIR/e3_bpf_test.o" "$OWNED_DIR/e3_bpf_validate.o" "$OWNED_DIR/e3_bpf_host.o" \
    -Wl,--start-group \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libbpf.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libelf.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libz.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libzstd.a" \
    -Wl,--end-group -pthread -Wl,-z,relro,-z,now,-z,noexecstack \
    -o "$OWNED_DIR/e3_bpf_host_linkcheck"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$OWNED_DIR/tmp" \
    "$CLANG_BIN" -O2 -g -target bpfel -D__TARGET_ARCH_x86 -nostdinc \
    -isystem "$CLANG_RESOURCE/include" -isystem /usr/include/x86_64-linux-gnu \
    -isystem /usr/include -I"$STAGED_PREFIX/usr/include" -I"$REPO_ROOT/proof" \
    -MD -MF "$OWNED_DIR/e3_bpf_exec.bpf.d" -c "$REPO_ROOT/proof/e3_bpf_exec.bpf.c" \
    -o "$OWNED_DIR/e3_bpf_exec.bpf.o"
  validate_bpf_obj_main "$READELF_BIN" "$OWNED_DIR/e3_bpf_exec.bpf.o" \
    "$OWNED_DIR/e3_bpf_exec.bpf.d" "$CLANG_RESOURCE" "$STAGED_PREFIX" \
    "$REPO_ROOT" "$LOCK_FILE" "$OWNED_DIR" e3
  for unit in e3_bpf_validate e3_bpf_test e3_bpf_host; do
    validate_host_elf_main "$READELF_BIN" "$OWNED_DIR/e3_bpf_host_linkcheck" \
      "$OWNED_DIR/$unit.d" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" \
      "$OWNED_DIR" "$LOCK_FILE" "$unit"
    cp "$OWNED_DIR/compiled-headers.json" "$OWNED_DIR/$unit-headers.json"
  done
  validate_host_elf_main "$READELF_BIN" "$OWNED_DIR/e3_bpf_test" \
    "$OWNED_DIR/e3_bpf_test.d" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" \
    "$OWNED_DIR" "$LOCK_FILE" e3_bpf_test_pure
  cp "$OWNED_DIR/compiled-headers.json" "$OWNED_DIR/e3_bpf_test_pure-headers.json"
  if /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$OWNED_DIR/tmp" \
      "$OWNED_DIR/e3_bpf_test" >"$OWNED_DIR/e3-pure-test.log" 2>&1; then
    printf '0\n' >"$OWNED_DIR/e3-pure-test.exit"
  else
    rc=$?
    printf '%s\n' "$rc" >"$OWNED_DIR/e3-pure-test.exit"
    exit "$rc"
  fi
  python3 -I - "$OWNED_DIR" "$LOCK_FILE" "$RECEIPT_FILE" "$CLANG_BIN" "$GCC_BIN" "$READELF_BIN" "$REPO_ROOT" <<'PY'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1])
record = json.loads((out / "e3-subject.json").read_text())
names = ["e3_bpf_validate.o", "e3_bpf_test.o", "e3_bpf_host.o",
         "e3_bpf_test", "e3_bpf_host_linkcheck", "e3_bpf_exec.bpf.o",
         "e3_bpf_validate.d", "e3_bpf_test.d", "e3_bpf_host.d",
         "e3_bpf_exec.bpf.d", "bpf-compiled-headers.json",
         "e3_bpf_validate-headers.json", "e3_bpf_test-headers.json",
         "e3_bpf_host-headers.json", "e3_bpf_test_pure-headers.json",
         "e3-pure-test.log", "e3-pure-test.exit"]
paths = [out / name for name in names] + [pathlib.Path(p) for p in sys.argv[2:7]]
paths += [pathlib.Path("/lib/x86_64-linux-gnu/libc.so.6"),
          pathlib.Path("/lib64/ld-linux-x86-64.so.2")]
repo = pathlib.Path(sys.argv[7])
paths += [repo / "proof/bpf_runner_baseline.py",
          repo / "proof/bpf_baseline_process.py",
          repo / "proof/bpf_tool_baseline.json",
          repo / "proof/bpf_gcc_include_baseline.json"]
paths += [out / "staged-prefix/usr/lib/x86_64-linux-gnu" / name
          for name in ("libbpf.a", "libelf.a", "libz.a", "libzstd.a")]
record["artifacts"] = {str(p): {"size": p.stat().st_size,
                       "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in paths}
record["pure_test_exit"] = int((out / "e3-pure-test.exit").read_text())
record["build_status"] = "validated"
(out / "e3-build-record.json").write_text(json.dumps(record, indent=2) + "\n")
PY
  echo "E3 build and synthetic validator checks completed; strict eligibility remains false."
  exit 0
fi

# 3. Section 4: Exact BPF compilation
BPF_SRC="$REPO_ROOT/proof/bpf_canary.bpf.c"
BPF_OBJ="$OWNED_DIR/bpf_canary.bpf.o"
BPF_DEP="$OWNED_DIR/bpf_canary.bpf.d"

if [ ! -f "$BPF_SRC" ]; then
  echo "ERROR: BPF source '$BPF_SRC' not found" >&2
  exit 1
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Compiling BPF probe object with $CLANG_BIN..."
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$OWNED_DIR/tmp" \
  "$CLANG_BIN" \
  -O2 -g -target bpfel -D__TARGET_ARCH_x86 \
  -nostdinc \
  -isystem "$CLANG_RESOURCE/include" \
  -isystem /usr/include/x86_64-linux-gnu \
  -isystem /usr/include \
  -I"$STAGED_PREFIX/usr/include" \
  -I"$REPO_ROOT/proof" \
  -MD -MF "$BPF_DEP" \
  -c "$BPF_SRC" \
  -o "$BPF_OBJ"

if [ ! -f "$BPF_OBJ" ] || [ ! -s "$BPF_OBJ" ]; then
  echo "ERROR: BPF compilation failed to produce output object '$BPF_OBJ'" >&2
  exit 1
fi

# 4. Section 4: Exact native helper linkage with 4 explicit static archives
HOST_SRC="$REPO_ROOT/proof/bpf_canary_host.c"
HOST_BIN="$OWNED_DIR/bpf_canary_host"
HOST_DEP="$OWNED_DIR/bpf_canary_host.d"

if [ ! -f "$HOST_SRC" ]; then
  echo "ERROR: Host helper source '$HOST_SRC' not found" >&2
  exit 1
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Linking native host helper with $GCC_BIN and four static archives..."
fi

/usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C TMPDIR="$OWNED_DIR/tmp" \
  "$GCC_BIN" \
  -O2 -g -Wall -Wextra -fPIE -pie \
  -I"$STAGED_PREFIX/usr/include" \
  -I"$REPO_ROOT/proof" \
  -MD -MF "$HOST_DEP" \
  "$HOST_SRC" \
  -Wl,--start-group \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libbpf.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libelf.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libz.a" \
    "$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/libzstd.a" \
  -Wl,--end-group \
  -pthread \
  -Wl,-z,relro,-z,now,-z,noexecstack \
  -o "$HOST_BIN"

if [ ! -f "$HOST_BIN" ] || [ ! -x "$HOST_BIN" ]; then
  echo "ERROR: Native helper compilation failed to produce executable '$HOST_BIN'" >&2
  exit 1
fi

# 5. Section 5: Unprivileged readelf inspection and fail-closed artifact validation
validate_bpf_obj_main "$READELF_BIN" "$BPF_OBJ" "$BPF_DEP" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" "$LOCK_FILE" "$OWNED_DIR"
validate_host_elf_main "$READELF_BIN" "$HOST_BIN" "$HOST_DEP" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" "$OWNED_DIR" "$LOCK_FILE"

# Bind diagnostic build record JSON (Section 5)
python3 -I - <<'PY' "$OWNED_DIR" "$REPO_ROOT" "$LOCK_FILE" "$RECEIPT_FILE" "$BPF_OBJ" "$HOST_BIN" "$CLANG_BIN" "$GCC_BIN" "$READELF_BIN"
import hashlib, json, os, pathlib, platform, sys

owned_dir = pathlib.Path(sys.argv[1])
repo_root = pathlib.Path(sys.argv[2])
lock_file = pathlib.Path(sys.argv[3])
receipt_file = pathlib.Path(sys.argv[4])
bpf_obj = pathlib.Path(sys.argv[5])
host_bin = pathlib.Path(sys.argv[6])
clang_bin = sys.argv[7]
gcc_bin = sys.argv[8]
readelf_bin = sys.argv[9]

def sha256_file(p):
    if not os.path.exists(p):
        return "MISSING"
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

compiled_headers_file = owned_dir / "compiled-headers.json"
compiled_headers = {}
if compiled_headers_file.is_file():
    compiled_headers = json.loads(compiled_headers_file.read_text(encoding="utf-8"))

record = {
    "schema": "iyi-bpf-build-record-v1",
    "strict_eligible": False,
    "source_checkout_sha": os.environ.get("GITHUB_SHA", "LOCAL_DEV"),
    "tools": {
        "clang": {"path": clang_bin, "sha256": sha256_file(clang_bin)},
        "gcc": {"path": gcc_bin, "sha256": sha256_file(gcc_bin)},
        "readelf": {"path": readelf_bin, "sha256": sha256_file(readelf_bin)},
    },
    "dynamic_dependencies": {
        "libc": {"path": "/lib/x86_64-linux-gnu/libc.so.6", "sha256": sha256_file("/lib/x86_64-linux-gnu/libc.so.6")},
        "ld_linux": {"path": "/lib64/ld-linux-x86-64.so.2", "sha256": sha256_file("/lib64/ld-linux-x86-64.so.2")},
    },
    "dependency_lock": {"path": str(lock_file), "sha256": sha256_file(lock_file)},
    "dependency_receipt": {"path": str(receipt_file), "sha256": sha256_file(receipt_file)},
    "compiled_source_and_header_digests": compiled_headers,
    "outputs": {
        "bpf_obj": {"path": str(bpf_obj), "sha256": sha256_file(bpf_obj)},
        "host_bin": {"path": str(host_bin), "sha256": sha256_file(host_bin)},
    },
    "uname": platform.uname()._asdict(),
    "btf_vmlinux": {"path": "/sys/kernel/btf/vmlinux", "sha256": sha256_file("/sys/kernel/btf/vmlinux")},
}

record_file = owned_dir / "diagnostic-build-record.json"
record_file.write_text(json.dumps(record, indent=2))
print(f"Recorded diagnostic build record at {record_file}")
PY
validate_build_integrity_main "$OWNED_DIR" "$BPF_OBJ" "$HOST_BIN"


if [ "$BUILD_ONLY" -eq 1 ]; then
  echo "Build-only mode requested; artifact build and verification complete."
  exit 0
fi

# 6. Section 7: Launch only the restricted foreground helper
# Recheck before the restricted helper launch; this never executes sudo.
python3 -I "$REPO_ROOT/proof/bpf_runner_baseline.py"

PROBE_UID="$(id -u)"
PROBE_GID="$(id -g)"

if [ "$PROBE_UID" -eq 0 ] || [ "$PROBE_GID" -eq 0 ]; then
  echo "ERROR: Refusing to launch probe as root UID ($PROBE_UID) or GID ($PROBE_GID)" >&2
  exit 1
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Validating headers and binaries immediately before capability launch..."
fi

validate_build_integrity_main "$OWNED_DIR" "$BPF_OBJ" "$HOST_BIN"

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Launching restricted foreground helper with /usr/bin/setpriv (UID=$PROBE_UID, GID=$PROBE_GID)..."
fi

# Foreground execution with dropped capabilities; no CAP_SYS_ADMIN
/usr/bin/sudo -n /usr/bin/setpriv \
  --reuid="$PROBE_UID" --regid="$PROBE_GID" --clear-groups \
  --bounding-set=-all,+bpf,+perfmon \
  --inh-caps=-all,+bpf,+perfmon \
  --ambient-caps=-all,+bpf,+perfmon \
  --no-new-privs \
  -- /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C \
  "$HOST_BIN" \
  --probe-only --verbose \
  --bpf-obj "$BPF_OBJ" \
  --status "$STATUS_FILE"

# 7. Evaluate terminal report JSON against Section 7 / acceptance criteria
evaluate_report_main "$STATUS_FILE"
