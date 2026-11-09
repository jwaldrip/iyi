#!/usr/bin/env bash
# proof/run_bpf_feasibility.sh: One shared unprivileged build, artifact validation,
# and restricted launcher entry point for BPF kernel feasibility diagnostics.
# Implements sections 4, 5, and 7 of agent://PlanBpfOwnedDependencies.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: proof/run_bpf_feasibility.sh [OPTIONS]

Options:
  --lock <path>             Path to bpf_dependencies.lock.json (default: proof/bpf_dependencies.lock.json)
  --dependency-script <path> Path to bpf_dependencies.py (default: proof/bpf_dependencies.py)
  --prefix <path>           Pre-staged dependency prefix (optional; if omitted, runs dependency script)
  --receipt <path>          Pre-staged dependency receipt JSON (required if --prefix is given)
  --owned-dir <path>        Scratch directory for build artifacts and reports
  --status <path>           Path to write bpf-feasibility.json report
  --build-only              Perform build and readelf artifact validation only; skip setpriv/helper launch
  --skip-launch             Alias for --build-only
  --verbose                 Enable verbose progress logging
  -h, --help                Show this help message and exit
EOF
}

LOCK_FILE="proof/bpf_dependencies.lock.json"
DEP_SCRIPT="proof/bpf_dependencies.py"
STAGED_PREFIX=""
RECEIPT_FILE=""
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
    --dependency-script)
      DEP_SCRIPT="$2"
      shift 2
      ;;
    --prefix)
      STAGED_PREFIX="$2"
      shift 2
      ;;
    --receipt)
      RECEIPT_FILE="$2"
      shift 2
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Section 4: Clear inherited build variables and package-manager configuration
unset CPATH C_INCLUDE_PATH LIBRARY_PATH LD_LIBRARY_PATH LD_PRELOAD CFLAGS LDFLAGS PKG_CONFIG_PATH

# Check for unexpected preload configuration
if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
  echo "ERROR: /etc/ld.so.preload exists and is non-empty; unexpected preload configuration" >&2
  exit 1
fi

# Set up owned private scratch directory with umask 077
if [ -z "$OWNED_DIR" ]; then
  if [ -n "${RUNNER_TEMP:-}" ] && [ -d "$RUNNER_TEMP" ]; then
    OWNED_DIR="$RUNNER_TEMP/bpf-feasibility-private"
    mkdir -m 0700 -p "$OWNED_DIR"
  else
    OLD_UMASK="$(umask)"
    umask 077
    OWNED_DIR="$(mktemp -d "${TMPDIR:-/tmp}/bpf-feasibility.XXXXXX")"
    umask "$OLD_UMASK"
  fi
else
  mkdir -m 0700 -p "$OWNED_DIR"
fi

mkdir -m 0700 -p "$OWNED_DIR/tmp"

if [ -z "$STATUS_FILE" ]; then
  STATUS_FILE="$OWNED_DIR/bpf-feasibility.json"
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Repository root: $REPO_ROOT"
  echo "[run_bpf_feasibility] Scratch working directory: $OWNED_DIR"
fi

# 1. Dependency staging and verification via shared contract
if [ ! -f "$LOCK_FILE" ]; then
  echo "ERROR: Dependency lock '$LOCK_FILE' not found" >&2
  exit 1
fi

if [ -z "$STAGED_PREFIX" ]; then
  if [ ! -f "$DEP_SCRIPT" ]; then
    echo "ERROR: Dependency script '$DEP_SCRIPT' not found and no --prefix supplied" >&2
    exit 1
  fi

  STAGED_PREFIX="$OWNED_DIR/staged-prefix"
  RECEIPT_FILE="$OWNED_DIR/bpf-dependency-receipt.json"

  if [ "$VERBOSE" -eq 1 ]; then
    echo "[run_bpf_feasibility] Invoking dependency slice: python3 $DEP_SCRIPT --lock $LOCK_FILE --output $STAGED_PREFIX --receipt $RECEIPT_FILE"
  fi

  python3 "$DEP_SCRIPT" --lock "$LOCK_FILE" --output "$STAGED_PREFIX" --receipt "$RECEIPT_FILE"
else
  if [ -z "$RECEIPT_FILE" ]; then
    # Look for adjacent receipt if not passed explicitly
    if [ -f "$OWNED_DIR/bpf-dependency-receipt.json" ]; then
      RECEIPT_FILE="$OWNED_DIR/bpf-dependency-receipt.json"
    elif [ -f "$STAGED_PREFIX/../bpf-dependency-receipt.json" ]; then
      RECEIPT_FILE="$STAGED_PREFIX/../bpf-dependency-receipt.json"
    elif [ -f "$STAGED_PREFIX/bpf-dependency-receipt.json" ]; then
      RECEIPT_FILE="$STAGED_PREFIX/bpf-dependency-receipt.json"
    else
      echo "ERROR: --prefix supplied without --receipt and no receipt found in standard locations" >&2
      exit 1
    fi
  fi
fi

# Independent cryptographic validation of staged dependency files against locked manifest
# Rejects arbitrary/forged receipts, modified archives, path escapes, and unauthenticated sources
python3 - <<'PY' "$LOCK_FILE" "$RECEIPT_FILE" "$STAGED_PREFIX"
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

# Prevent root / system path targets
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

# 2. Verify signer fingerprint against lock trust root
approved_signers = lock.get("trust_root", {}).get("approved_signer_fingerprints", [])
receipt_signer = receipt.get("signer_fingerprint")
if not receipt_signer or receipt_signer not in approved_signers:
    sys.exit(f"ERROR: Receipt signer '{receipt_signer}' not in approved signers: {approved_signers}")

# 3. Verify receipt prefix matches actual prefix
receipt_prefix_str = receipt.get("staged_prefix") or receipt.get("prefix")
if not receipt_prefix_str:
    sys.exit("ERROR: Receipt missing staged_prefix")
receipt_prefix = pathlib.Path(receipt_prefix_str).resolve()
if receipt_prefix != prefix_path:
    sys.exit(f"ERROR: Receipt prefix '{receipt_prefix}' does not match actual prefix '{prefix_path}'")

# 4. Independent staged file hash and size verification against locked manifest
packages = lock.get("packages", {})
required_pkgs = ["libbpf-dev", "libelf-dev", "libzstd-dev", "zlib1g-dev"]
for pkg in required_pkgs:
    if pkg not in packages:
        sys.exit(f"ERROR: Required package '{pkg}' missing from dependency lock")
    pkg_info = packages[pkg]

    # Check deb digest in receipt
    rec_pkg = (receipt.get("packages") or {}).get(pkg) or (receipt.get("archives") or {}).get(pkg)
    if not rec_pkg:
        sys.exit(f"ERROR: Package '{pkg}' missing from receipt packages summary")
    rec_deb_sha = rec_pkg.get("deb_sha256") or (rec_pkg if isinstance(rec_pkg, str) else None)
    if rec_deb_sha and rec_deb_sha.lower() != pkg_info.get("sha256", "").lower():
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

    # Verify all required headers exist
    headers = pkg_info.get("required_headers", [])
    for hdr in headers:
        hdr_path = prefix_path / hdr
        if not hdr_path.is_file():
            sys.exit(f"ERROR: Required header '{hdr}' missing from staged prefix (fail-closed, no host fallback)")

print("Independent verification: all staged archives and headers cryptographically bound to authenticated lock.")
PY

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
python3 - <<'PY' "$READELF_BIN" "$BPF_OBJ" "$BPF_DEP" "$HOST_BIN" "$CLANG_RESOURCE" "$STAGED_PREFIX" "$REPO_ROOT" "$OWNED_DIR"
import hashlib, json, os, pathlib, subprocess, sys

readelf_bin = sys.argv[1]
bpf_obj = sys.argv[2]
bpf_dep = sys.argv[3]
host_bin = sys.argv[4]
clang_res = sys.argv[5]
prefix = sys.argv[6]
repo_root = sys.argv[7]
owned_dir = sys.argv[8]

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

# Section 5: Parse real .BTF.ext CO-RE relocation records directly from binary ELF structure
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

# Walk core_relo sections and count total relocation records
relo_idx = 4
total_core_relocs = 0
while relo_idx + 8 <= len(relo_bytes):
    sec_name_off = int.from_bytes(relo_bytes[relo_idx : relo_idx + 4], "little")
    num_info = int.from_bytes(relo_bytes[relo_idx + 4 : relo_idx + 8], "little")
    relo_idx += 8
    expected_data_len = num_info * rec_size
    if relo_idx + expected_data_len > len(relo_bytes):
        sys.exit("ERROR: .BTF.ext core_relo section records exceed bounds")
    total_core_relocs += num_info
    relo_idx += expected_data_len

if total_core_relocs == 0:
    sys.exit("ERROR: .BTF.ext contains 0 CO-RE relocation records")

print(f"Verified real .BTF.ext CO-RE relocations: {total_core_relocs} records ({core_relo_len} bytes)")

# Header dependency check from .d file
allowed_prefixes = [
    str(pathlib.Path(clang_res).resolve()),
    "/usr/include/x86_64-linux-gnu",
    "/usr/include",
    str(pathlib.Path(prefix).resolve()),
    str(pathlib.Path(repo_root).resolve()),
]
if os.path.exists(bpf_dep):
    with open(bpf_dep, "r", encoding="utf-8") as f:
        dep_content = f.read().replace("\\\n", " ")
    tokens = dep_content.split()
    for tok in tokens[1:]:  # skip target object
        if tok.endswith(".o:") or tok.endswith(":"):
            continue
        p = str(pathlib.Path(tok).resolve())
        if not any(p.startswith(allowed) for allowed in allowed_prefixes):
            sys.exit(f"ERROR: BPF object included unapproved header dependency: '{tok}'")

# --- Validate Native Host Helper ---
host_hdr = run_readelf("-hW", host_bin)
if "ELF64" not in host_hdr:
    sys.exit("ERROR: Host helper is not ELF64")
if "X86-64" not in host_hdr and "x86-64" not in host_hdr:
    sys.exit("ERROR: Host helper machine is not x86-64")

host_dyn = run_readelf("-dW", host_bin)
needed = []
for line in host_dyn.splitlines():
    if "(NEEDED)" in line or "Shared library:" in line:
        needed.append(line.strip())
    if "RPATH" in line or "RUNPATH" in line:
        sys.exit(f"ERROR: Disallowed RPATH/RUNPATH found in host helper: {line.strip()}")

# Expected DT_NEEDED set: libc.so.6 only
if not needed:
    sys.exit("ERROR: Host helper has no DT_NEEDED entries; expected libc.so.6")
for entry in needed:
    if "libc.so.6" not in entry:
        sys.exit(f"ERROR: Disallowed dynamic dependency in host helper (only libc.so.6 allowed): {entry}")

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

print("All artifact validation criteria passed (BPF object with verified .BTF.ext CO-RE relocations and statically linked host helper with non-executable stack).")
PY

# Bind diagnostic build record JSON (Section 5)
python3 - <<'PY' "$OWNED_DIR" "$REPO_ROOT" "$LOCK_FILE" "$RECEIPT_FILE" "$BPF_OBJ" "$HOST_BIN" "$CLANG_BIN" "$GCC_BIN" "$READELF_BIN"
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
SETPRIV_BIN="/usr/bin/setpriv"
if [ ! -x "$SETPRIV_BIN" ]; then
  SETPRIV_BIN="$(command -v setpriv 2>/dev/null || true)"
fi
if [ -z "$SETPRIV_BIN" ] || [ ! -x "$SETPRIV_BIN" ]; then
  echo "ERROR: setpriv utility missing; cannot launch restricted foreground observer" >&2
  exit 1
fi

PROBE_UID="$(id -u)"
PROBE_GID="$(id -g)"

if [ "$PROBE_UID" -eq 0 ] || [ "$PROBE_GID" -eq 0 ]; then
  echo "ERROR: Refusing to launch probe as root UID ($PROBE_UID) or GID ($PROBE_GID)" >&2
  exit 1
fi

if [ "$VERBOSE" -eq 1 ]; then
  echo "[run_bpf_feasibility] Launching restricted foreground helper with setpriv (UID=$PROBE_UID, GID=$PROBE_GID)..."
fi

# Foreground execution with dropped capabilities; no CAP_SYS_ADMIN
sudo -n "$SETPRIV_BIN" \
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
python3 - <<'PY' "$STATUS_FILE"
import json, sys

status_file = sys.argv[1]
with open(status_file, "r", encoding="utf-8") as f:
    r = json.load(f)

p = r.get("observed_kernel_prog") or {}
l = r.get("observed_kernel_link") or {}
caps = r.get("capabilities") or {}
proc = r.get("process_identity") or {}
memlock = r.get("memlock") or {}
verifier = r.get("verifier_evidence") or {}

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
)

if not ok:
    sys.exit(f"BPF terminal report is incomplete or inconsistent:\n{json.dumps(r, indent=2)}")

print("BPF terminal diagnostic feasibility report verified successfully.")
PY
