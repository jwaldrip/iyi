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
  --lock <path>             Path to bpf_dependencies.lock.json (default: proof/bpf_dependencies.lock.json)
  --owned-dir <path>        Scratch directory for build artifacts and reports
  --status <path>           Path to write bpf-feasibility.json report
  --build-only              Perform build and artifact validation only; skip setpriv/helper launch
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
if "sched_process_exec" not in bpf_sym:
    sys.exit("ERROR: BPF object missing expected program symbol 'sched_process_exec'")

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
for i in range(e_shnum):
    sh = bpf_raw[e_shoff + i * e_shentsize : e_shoff + (i + 1) * e_shentsize]
    name_off = int.from_bytes(sh[0:4], "little")
    name = shstrtab[name_off:].split(b"\x00", 1)[0].decode("latin1")
    sh_offset = int.from_bytes(sh[24:32], "little")
    sh_size = int.from_bytes(sh[32:40], "little")
    sections[name] = bpf_raw[sh_offset : sh_offset + sh_size]

# --- Parse .BTF string and type table ---
if ".BTF" not in sections:
    sys.exit("ERROR: .BTF section missing from BPF object")

btf_raw = sections[".BTF"]
if len(btf_raw) < 24:
    sys.exit("ERROR: .BTF section too short")

btf_hdr_magic = int.from_bytes(btf_raw[0:2], "little")
if btf_hdr_magic != 0xEB9F:
    sys.exit(f"ERROR: .BTF magic mismatch: 0x{btf_hdr_magic:04x}")

btf_hdr_len = int.from_bytes(btf_raw[4:8], "little")
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

while t_idx + 12 <= len(type_bytes):
    name_off = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
    info = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little")
    size_or_type = int.from_bytes(type_bytes[t_idx+8:t_idx+12], "little")
    t_idx += 12

    kind = (info >> 24) & 0x1F
    vlen = info & 0xFFFF
    name = get_btf_string(name_off)

    members = []
    if kind in (4, 5):  # STRUCT, UNION
        for _ in range(vlen):
            if t_idx + 12 > len(type_bytes):
                sys.exit("ERROR: .BTF struct member truncated")
            m_name_off = int.from_bytes(type_bytes[t_idx:t_idx+4], "little")
            m_type = int.from_bytes(type_bytes[t_idx+4:t_idx+8], "little")
            m_off = int.from_bytes(type_bytes[t_idx+8:t_idx+12], "little")
            t_idx += 12
            members.append({"name": get_btf_string(m_name_off), "type": m_type, "offset": m_off})
    elif kind == 1:  # INT
        t_idx += 4
    elif kind == 3:  # ARRAY
        t_idx += 12
    elif kind in (6, 13):  # ENUM, FUNC_PROTO
        t_idx += vlen * 8
    elif kind == 14:  # VAR
        t_idx += 4
    elif kind == 15:  # DATASEC
        t_idx += vlen * 12
    elif kind == 17:  # DECL_TAG
        t_idx += 4
    elif kind == 19:  # ENUM64
        t_idx += vlen * 12

    btf_types[type_id] = {"name": name, "kind": kind, "size_or_type": size_or_type, "members": members}
    type_id += 1

if not btf_types:
    sys.exit("ERROR: .BTF contains 0 parsed types")

# --- Parse and Validate .BTF.ext CO-RE Relocation Records ---
if ".BTF.ext" not in sections:
    sys.exit("ERROR: .BTF.ext section missing from BPF object")

btf_ext = sections[".BTF.ext"]
if len(btf_ext) < 32:
    sys.exit("ERROR: .BTF.ext section too short to contain CO-RE header")

btf_magic = int.from_bytes(btf_ext[0:2], "little")
if btf_magic != 0xEB9F:
    sys.exit(f"ERROR: .BTF.ext magic mismatch: expected 0xeb9f, got 0x{btf_magic:04x}")

hdr_len = int.from_bytes(btf_ext[4:8], "little")
if hdr_len < 32:
    sys.exit(f"ERROR: .BTF.ext header length {hdr_len} too small for CO-RE relocations")

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

while relo_idx + 8 <= len(relo_bytes):
    sec_name_off = int.from_bytes(relo_bytes[relo_idx : relo_idx + 4], "little")
    num_info = int.from_bytes(relo_bytes[relo_idx + 4 : relo_idx + 8], "little")
    relo_idx += 8

    sec_name = get_btf_string(sec_name_off)
    if not sec_name:
        sys.exit(f"ERROR: Invalid sec_name_off {sec_name_off} in .BTF.ext core_relo")

    if sec_name == "tp_btf/sched_process_exec":
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
        if sec_name == "tp_btf/sched_process_exec":
            if insn_off % 8 != 0 or insn_off >= prog_sec_len:
                sys.exit(f"ERROR: Invalid insn_off {insn_off} (not 8-byte aligned or >= {prog_sec_len})")

        # Validate access string
        access_str = get_btf_string(access_str_off)
        if not access_str or not access_str[0].isdigit():
            sys.exit(f"ERROR: Invalid CO-RE access string at offset {access_str_off}: '{access_str}'")

        # Validate kind (0..9)
        if kind not in range(0, 10):
            sys.exit(f"ERROR: Disallowed CO-RE kind: {kind}")

        total_core_relocs += 1

if not found_target_section:
    sys.exit("ERROR: .BTF.ext lacks relocations for 'tp_btf/sched_process_exec'")

if total_core_relocs < 10:
    sys.exit(f"ERROR: Expected >= 10 genuine CO-RE relocations, found {total_core_relocs}")

print(f"Verified genuine .BTF.ext CO-RE relocations: {total_core_relocs} valid records ({core_relo_len} bytes) for tp_btf/sched_process_exec.")

# Header dependency check from .d file
allowed_prefixes = [
    str(pathlib.Path(clang_res).resolve()),
    "/usr/include/x86_64-linux-gnu",
    "/usr/include",
    str(prefix_path),
    str(repo_path),
]

if os.path.exists(bpf_dep):
    with open(bpf_dep, "r", encoding="utf-8") as f:
        dep_content = f.read().replace("\\\n", " ")
    tokens = dep_content.split()
    for tok in tokens[1:]:
        if tok.endswith(".o:") or tok.endswith(":"):
            continue
        p = pathlib.Path(tok).resolve()
        p_str = str(p)
        if not any(p_str.startswith(allowed) for allowed in allowed_prefixes):
            sys.exit(f"ERROR: BPF object included unapproved header dependency: '{tok}'")
        if p_str.startswith(str(prefix_path)):
            rel_hdr = str(p.relative_to(prefix_path))
            if rel_hdr not in all_locked_headers:
                sys.exit(f"ERROR: BPF object included unapproved header from staged prefix: '{rel_hdr}'")
            hdr_bytes = p.read_bytes()
            actual_hdr_sha = hashlib.sha256(hdr_bytes).hexdigest()
            expected_hdr_info = all_locked_headers[rel_hdr]
            if "sha256" in expected_hdr_info and actual_hdr_sha.lower() != expected_hdr_info["sha256"].lower():
                sys.exit(f"ERROR: BPF object included header '{rel_hdr}' whose SHA256 does not match lock")
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
required_symbols = ["bpf_object__open_file", "bpf_object__load", "elf_begin", "deflate", "ZSTD_decompress"]
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

compiled_source_header_digests = {}

if os.path.exists(host_dep):
    with open(host_dep, "r", encoding="utf-8") as f:
        dep_content = f.read().replace("\\\n", " ")
    tokens = dep_content.split()
    for tok in tokens[1:]:
        if tok.endswith(".o:") or tok.endswith(":"):
            continue
        p = pathlib.Path(tok).resolve()
        p_str = str(p)
        if not any(p_str.startswith(allowed) for allowed in allowed_prefixes):
            sys.exit(f"ERROR: Host helper included unapproved dependency from untrusted path: '{tok}'")
        if p.is_file():
            hdr_bytes = p.read_bytes()
            actual_hdr_sha = hashlib.sha256(hdr_bytes).hexdigest()
            compiled_source_header_digests[p_str] = {
                "sha256": actual_hdr_sha,
                "size": len(hdr_bytes)
            }
            if p_str.startswith(str(prefix_path)):
                rel_hdr = str(p.relative_to(prefix_path))
                if rel_hdr not in all_locked_headers:
                    sys.exit(f"ERROR: Host helper included unapproved header from staged prefix: '{rel_hdr}'")
                expected_hdr_info = all_locked_headers[rel_hdr]
                if "sha256" in expected_hdr_info and actual_hdr_sha.lower() != expected_hdr_info["sha256"].lower():
                    sys.exit(f"ERROR: Host helper included header '{rel_hdr}' whose SHA256 does not match lock")
        else:
            sys.exit(f"ERROR: Host dependency '{p_str}' missing on disk during graph validation")

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

# Check for sub-actions invoked for direct testing
if [ $# -gt 0 ]; then
  case "$1" in
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
VERBOSE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --lock)
      LOCK_FILE="$2"
      shift 2
      ;;
    --dependency-script|--prefix|--receipt)
      echo "ERROR: Option '$1' is forbidden; exact approved repository consumer proof/bpf_dependencies.py is bound" >&2
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

if [ ! -f "$LOCK_FILE" ]; then
  echo "ERROR: Dependency lock '$LOCK_FILE' not found" >&2
  exit 1
fi
if [ ! -f "$DEP_SCRIPT" ]; then
  echo "ERROR: Dependency script '$DEP_SCRIPT' not found" >&2
  exit 1
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

if [ -z "$STATUS_FILE" ]; then
  STATUS_FILE="$OWNED_DIR/bpf-feasibility.json"
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Repository root: $REPO_ROOT"
  echo "[run_bpf_feasibility] Scratch working directory: $OWNED_DIR"
fi

# 1. Dependency staging and verification via shared contract
STAGED_PREFIX="$OWNED_DIR/staged-prefix"
RECEIPT_FILE="$OWNED_DIR/bpf-dependency-receipt.json"

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Invoking authenticated dependency consumer: python3 -I $DEP_SCRIPT --lock $LOCK_FILE --output $STAGED_PREFIX --receipt $RECEIPT_FILE"
fi

python3 -I "$DEP_SCRIPT" --lock "$LOCK_FILE" --output "$STAGED_PREFIX" --receipt "$RECEIPT_FILE"

# Authoritative pre-compilation manifest validation
validate_staged_manifest_main "$LOCK_FILE" "$RECEIPT_FILE" "$STAGED_PREFIX"

# 2. Toolchain verification (Section 4)
CLANG_BIN=""
for candidate in /usr/bin/clang-18 /usr/bin/clang; do
  if [ -x "$candidate" ]; then
    CLANG_BIN="$candidate"
    break
  fi
done
if [ -z "$CLANG_BIN" ]; then
  CLANG_BIN="$(command -v clang-18 2>/dev/null || command -v clang 2>/dev/null || true)"
fi
if [ -z "$CLANG_BIN" ] || [ ! -x "$CLANG_BIN" ]; then
  echo "ERROR: Clang compiler not found; prerequisite failure" >&2
  exit 1
fi

CLANG_RESOURCE="$("$CLANG_BIN" -print-resource-dir 2>/dev/null || true)"
if [ -z "$CLANG_RESOURCE" ] || [ ! -d "$CLANG_RESOURCE/include" ]; then
  echo "ERROR: Clang resource directory invalid ('$CLANG_RESOURCE'); trusted toolchain failure" >&2
  exit 1
fi

GCC_BIN=""
for candidate in /usr/bin/gcc-13 /usr/bin/gcc; do
  if [ -x "$candidate" ]; then
    GCC_BIN="$candidate"
    break
  fi
done
if [ -z "$GCC_BIN" ]; then
  GCC_BIN="$(command -v gcc-13 2>/dev/null || command -v gcc 2>/dev/null || true)"
fi
if [ -z "$GCC_BIN" ] || [ ! -x "$GCC_BIN" ]; then
  echo "ERROR: GCC compiler not found; prerequisite failure" >&2
  exit 1
fi

READELF_BIN="$(command -v readelf 2>/dev/null || true)"
if [ -z "$READELF_BIN" ] && [ -x /usr/bin/readelf ]; then
  READELF_BIN="/usr/bin/readelf"
fi
if [ -z "$READELF_BIN" ]; then
  echo "ERROR: readelf utility not found; prerequisite failure" >&2
  exit 1
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
validate_bpf_obj_main "$READELF_BIN" "$BPF_OBJ" "$BPF_DEP" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" "$LOCK_FILE"
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

if [ "$BUILD_ONLY" -eq 1 ]; then
  echo "Build-only mode requested; artifact build and verification complete."
  exit 0
fi

# 6. Section 7: Launch only the restricted foreground helper
if [ ! -x /usr/bin/setpriv ]; then
  echo "ERROR: Trusted system binary /usr/bin/setpriv missing or not executable (no PATH fallback permitted)" >&2
  exit 1
fi

if [ ! -x /usr/bin/sudo ]; then
  echo "ERROR: Trusted system binary /usr/bin/sudo missing or not executable (no PATH fallback permitted)" >&2
  exit 1
fi

PROBE_UID="$(id -u)"
PROBE_GID="$(id -g)"

if [ "$PROBE_UID" -eq 0 ] || [ "$PROBE_GID" -eq 0 ]; then
  echo "ERROR: Refusing to launch probe as root UID ($PROBE_UID) or GID ($PROBE_GID)" >&2
  exit 1
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Validating headers and binaries immediately before capability launch..."
fi

# Pre-capability launch re-verification: verify compiled artifacts and staged headers have not been modified
python3 -I - <<'PY' "$OWNED_DIR" "$BPF_OBJ" "$HOST_BIN"
import hashlib, json, os, pathlib, sys

owned_dir = pathlib.Path(sys.argv[1])
bpf_obj = pathlib.Path(sys.argv[2])
host_bin = pathlib.Path(sys.argv[3])

headers_record_file = owned_dir / "compiled-headers.json"
if not headers_record_file.is_file():
    sys.exit("ERROR: compiled-headers.json record missing before launch")

recorded = json.loads(headers_record_file.read_text(encoding="utf-8"))
for file_path_str, expected_info in recorded.items():
    p = pathlib.Path(file_path_str)
    if not p.is_file():
        sys.exit(f"ERROR: Compiled header/source '{file_path_str}' missing before launch")
    actual_bytes = p.read_bytes()
    actual_sha = hashlib.sha256(actual_bytes).hexdigest()
    if actual_sha.lower() != expected_info["sha256"].lower():
        sys.exit(f"ERROR: Header/source tampering detected before capability launch for '{file_path_str}'")

build_record_file = owned_dir / "diagnostic-build-record.json"
if not build_record_file.is_file():
    sys.exit("ERROR: diagnostic-build-record.json missing before launch")
build_rec = json.loads(build_record_file.read_text(encoding="utf-8"))

expected_bpf_sha = build_rec["outputs"]["bpf_obj"]["sha256"]
actual_bpf_sha = hashlib.sha256(bpf_obj.read_bytes()).hexdigest()
if actual_bpf_sha.lower() != expected_bpf_sha.lower():
    sys.exit("ERROR: BPF object tampering detected before capability launch")

expected_host_sha = build_rec["outputs"]["host_bin"]["sha256"]
actual_host_sha = hashlib.sha256(host_bin.read_bytes()).hexdigest()
if actual_host_sha.lower() != expected_host_sha.lower():
    sys.exit("ERROR: Host helper binary tampering detected before capability launch")

print("Pre-capability launch validation: all headers, sources, and binaries verified unchanged.")
PY

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
