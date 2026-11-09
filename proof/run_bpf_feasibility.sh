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
if [ -z "$STAGED_PREFIX" ]; then
  if [ ! -f "$DEP_SCRIPT" ]; then
    echo "ERROR: Dependency script '$DEP_SCRIPT' not found and no --prefix supplied" >&2
    exit 1
  fi
  if [ ! -f "$LOCK_FILE" ]; then
    echo "ERROR: Dependency lock '$LOCK_FILE' not found and no --prefix supplied" >&2
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
    fi
  fi
fi

# Validate staged prefix and required four dev archives (Fail-closed, never fall back)
for h in usr/include/bpf/bpf.h usr/include/bpf/libbpf.h usr/include/libelf.h usr/include/zlib.h usr/include/zstd.h; do
  if [ ! -f "$STAGED_PREFIX/$h" ]; then
    echo "ERROR: Staged prefix missing required header: $STAGED_PREFIX/$h (fail-closed, no host package fallback)" >&2
    exit 1
  fi
done

for a in libbpf.a libelf.a libz.a libzstd.a; do
  arch_path="$STAGED_PREFIX/usr/lib/x86_64-linux-gnu/$a"
  if [ ! -f "$arch_path" ] || [ ! -s "$arch_path" ]; then
    echo "ERROR: Staged prefix missing required static archive: $arch_path (fail-closed, no host package fallback)" >&2
    exit 1
  fi
done

if [ -n "$RECEIPT_FILE" ] && [ -f "$RECEIPT_FILE" ]; then
  python3 - <<'PY' "$RECEIPT_FILE" "$STAGED_PREFIX"
import json, pathlib, sys
receipt_path = pathlib.Path(sys.argv[1]).resolve()
expected_prefix = pathlib.Path(sys.argv[2]).resolve()
with open(receipt_path, "r", encoding="utf-8") as f:
    r = json.load(f)

status = r.get("status")
if status not in ("SUCCESS", "VERIFIED"):
    sys.exit(f"ERROR: Dependency receipt status is '{status}', expected SUCCESS or VERIFIED")

receipt_prefix = pathlib.Path(r.get("prefix", "")).resolve()
if receipt_prefix != expected_prefix:
    sys.exit(f"ERROR: Receipt prefix mismatch: '{receipt_prefix}' != '{expected_prefix}'")

archives = r.get("archives") or r.get("archive_digests") or {}
required = ["libbpf-dev", "libelf-dev", "zlib1g-dev", "libzstd-dev"]
missing = [pkg for pkg in required if pkg not in archives]
if missing:
    sys.exit(f"ERROR: Dependency receipt missing verified digests for packages: {missing}")
PY
else
  echo "ERROR: Dependency receipt missing or unreadable; cannot prove authenticated archive origin" >&2
  exit 1
fi

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

# CO-RE relocation evidence in BPF object
bpf_rel = run_readelf("-rW", bpf_obj)
if "rel" not in bpf_rel and "Offset" not in bpf_rel:
    sys.exit("ERROR: BPF object lacks relocation records")

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

host_prog = run_readelf("-lW", host_bin)
if "/lib64/ld-linux-x86-64.so.2" not in host_prog:
    sys.exit("ERROR: Host helper interpreter mismatch; expected /lib64/ld-linux-x86-64.so.2")
if "GNU_STACK" in host_prog:
    for line in host_prog.splitlines():
        if "GNU_STACK" in line and "E" in line.split()[-1]:
            sys.exit("ERROR: Host helper has executable stack (GNU_STACK contains 'E')")

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

print("All artifact validation criteria passed (BPF object and statically linked host helper).")
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
