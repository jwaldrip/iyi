#!/usr/bin/env bash
# The native ELF gate (SPEC 2.3 and 3.4, slice D3: the object reader and writer, the static-PIE linker, and the Linux
# start code).
#
# 1. The drivers build from source: obj_elf (the object round trip) and link_elf (verify, start, stub, link).
# 2. Object round trip, both Linux architectures: for every samples/iyi and bench/fixtures/native_obj program the
#    oracle compiler emits an ELF object with --cross-compile --target <triple>. The native reader reads it, the native
#    writer writes it back, and the reader must read the result equal to the first read. The `llvm-readelf -S -s -r -W`
#    listing of the rewritten object must equal the original's, except the two lines that depend on the string table's
#    size: the section header table offset and the .strtab row. The writer lays the string table out without tail
#    merging, so its size differs; every other listed byte is the same. Objects with COMDAT group sections are refused
#    by the object reader, and are reported as excluded with that reason.
# 3. Relocation coverage over the corpus: each ELF relocation kind with its count, zero counts included.
# 4. Mutation proofs (object reader and writer; linker): each patch must be caught by its check. A patch whose text is
#    absent fails the gate, because it would prove nothing.
# 5. Start code: both Linux start IRs verify. The aarch64 one compiles through the native backend to an ELF object.
#    Both are also translated by iyi-ir (the LLVM bridge, SPEC 3.3) and compiled by llc into bridged ELF objects. The
#    x86_64 executables link against the bridged object, until the x86_64 code generator (slice D2) compiles the start.
# 6. Executables: every corpus program for both architectures is linked as a static-PIE and checked structurally by
#    bench/fixtures/native_elf/check_exe.py (no PT_INTERP, no PT_DYNAMIC, PT_TLS where TLS is used, GNU_STACK read-write,
#    PT_GNU_RELRO, no crt symbols, no .comment, the entry point at _start, and every relative relocation entry non-zero
#    and inside an allocated section). The x86_64 executables link against the bridged start object, so they are
#    checked and never run here.
# 7. Each executable links twice to identical bytes (cmp).
# 8. Linux runs, not done on this host: each aarch64 and x86_64 program run and its stdout and exit status compared
#    with the oracle binary, and the address-randomisation fixture run twice. These print a skip line and need the Linux
#    job that runs them (native-arm64-linux and native-linux). The mutations that only a run can see are listed there.
# 9. The run half. `--emit DIR` writes DIR/<arch>/ with each program's oracle object, its native executable and a
#    MANIFEST. `sh bench/native_elf_run.sh DIR <arch>` runs them on a Linux host of that architecture. This gate checks
#    that the emitted set equals what the script's --list expects, and that the script parses.
#
# Needs a built compiler (`make`). Runs the object and structural steps on any host; nothing here invokes a host tool
# to build an executable.

set -u

emit_dir=""
if [ "${1:-}" = "--emit" ]; then
  [ -n "${2:-}" ] || { echo "usage: bench/native_elf_exercise.sh [--emit DIR]" >&2; exit 2; }
  mkdir -p "$2" && emit_dir="$(cd "$2" && pwd)" || exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
cd "$root" || exit 1

iyi=./bin/iyi
obj_src=src/compiler/tools/obj_elf.iyi
link_src=src/compiler/tools/link_elf.iyi
elf_src=src/compiler/native/obj/elf.iyi
exe_src=src/compiler/native/link/elf_exe.iyi
asm_src=src/compiler/native/aarch64/asm.iyi
check=bench/fixtures/native_elf/check_exe.py
start_a64_ir=src/compiler/native/rt/start_linux_aarch64.ir
start_x86_ir=src/compiler/native/rt/start_linux_x86_64.ir
arches="x86_64-linux-gnu aarch64-linux-gnu"

work="$(mktemp -d "${TMPDIR:-/tmp}/native_elf.XXXXXX")" || exit 1
restore=""
backup=""
cleanup() {
  if [ -n "$restore" ] && [ -n "$backup" ]; then
    cp "$backup" "$restore"
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

failures=0
fail() {
  echo "   $*"
  failures=$((failures + 1))
}

# The object file's machine, for the name a corpus object is keyed by.
arch_short() {
  case "$1" in
    x86_64-linux-gnu) echo x86_64 ;;
    aarch64-linux-gnu) echo aarch64 ;;
  esac
}

# build_tools: builds both drivers from the current source into $work/bin.
build_tools() {
  mkdir -p "$work/bin"
  "$iyi" build -o "$work/bin/obj_elf" "$obj_src" >"$work/build-obj.log" 2>&1 || return 1
  "$iyi" build -o "$work/bin/link_elf" "$link_src" >"$work/build-link.log" 2>&1 || return 1
}

# filtered_listing FILE: the llvm-readelf listing of FILE without the two string-table-dependent lines.
filtered_listing() {
  llvm-readelf -S -s -r -W "$1" 2>&1 | awk '!/section headers, starting at offset/ && !/ \.strtab /'
}

# oracle_flags BUILD_LOG: the link flags of the hosted compiler's link line for the cross-compiled object (cc OBJECT -o
# EXE FLAGS, minus the host library directory), as one word, or `-` when it has none.
oracle_flags() {
  awk '/^cc /{ out = ""; for (i = 5; i <= NF; i++) if ($i !~ /^-L/) out = out " " $i; sub(/^ /, "", out); print (out == "" ? "-" : out); exit }' "$1"
}

# run_program EXE OUT: runs EXE from a scratch directory with no stdin for at most 30 seconds, writing stdout to OUT
# and printing the exit status. Only used where the host runs the architecture (never on this host for Linux).
run_program() {
  rundir="$work/run"
  mkdir -p "$rundir"
  (cd "$rundir" && perl -e 'alarm 30; exec @ARGV' "$1" </dev/null >"$2" 2>/dev/null)
  echo $?
}

# prove_mutation LABEL FILE OLD NEW CHECK...: replaces the first OLD in FILE with NEW, runs CHECK, and requires it to
# fail. Restores FILE on every exit path.
prove_mutation() {
  label=$1
  file=$2
  old=$3
  new=$4
  shift 4
  backup="$work/mutation-$RANDOM.bak"
  cp "$file" "$backup" || return 1
  restore="$file"
  python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
  patched=$?
  if [ "$patched" -eq 3 ]; then
    cp "$backup" "$file"
    restore=""
    fail "PATCH CHANGED NOTHING: '$label' found no text to change"
    return 1
  fi
  if [ "$patched" -ne 0 ]; then
    cp "$backup" "$file"
    restore=""
    fail "could not apply '$label'"
    return 1
  fi
  if "$@" >"$work/mutation-check.log" 2>&1; then
    fail "NOT caught: $label"
  else
    echo "   caught: $label"
  fi
  cp "$backup" "$file"
  restore=""
  return 0
}

echo "== 1. build the drivers from the source"
if ! build_tools; then
  echo "   a driver does not build:"
  tail -n 20 "$work/build-obj.log" "$work/build-link.log"
  echo "== SOME NATIVE_ELF CHECKS FAILED"
  exit 1
fi
cp "$work/bin/obj_elf" "$work/bin/obj_elf.good"
cp "$work/bin/link_elf" "$work/bin/link_elf.good"
echo "   obj_elf and link_elf built"

echo "== 2. object round trip, both Linux architectures"
objects_total=0
excluded_total=0
for triple in $arches; do
  short="$(arch_short "$triple")"
  mkdir -p "$work/obj/$short"
  : >"$work/obj/$short/coverage.txt"
  ok=0
  for src in samples/iyi/*.iyi bench/fixtures/native_obj/*.iyi bench/fixtures/native_elf/*.iyi; do
    [ -f "$src" ] || continue
    name="$(basename "$src" .iyi)"
    obj="$work/obj/$short/$name.o"
    if ! "$iyi" build --cross-compile --target "$triple" -o "$obj" "$src" \
        >"$work/obj/$short/$name.build" 2>"$work/obj/$short/$name.err"; then
      fail "the oracle does not compile $src for $triple"
      continue
    fi
    objects_total=$((objects_total + 1))
    rt="$work/obj/$short/$name.rt.o"
    if ! "$work/bin/obj_elf" "$obj" "$rt" >"$work/obj/$short/$name.rt.log" 2>&1; then
      if grep -q "type 17" "$work/obj/$short/$name.rt.log"; then
        echo "   $short $name: excluded, COMDAT group sections, which the object reader refuses by name"
        excluded_total=$((excluded_total + 1))
        continue
      fi
      fail "$short $name does not round trip:"
      sed 's/^/     /' "$work/obj/$short/$name.rt.log" | tail -n 3
      continue
    fi
    if ! grep -q "^ROUNDTRIP EQUAL" "$work/obj/$short/$name.rt.log"; then
      fail "$short $name: the round trip did not report equality"
      continue
    fi
    if ! diff <(filtered_listing "$obj") <(filtered_listing "$rt") >"$work/obj/$short/$name.diff"; then
      fail "$short $name: the rewritten object's listing differs:"
      sed 's/^/     /' "$work/obj/$short/$name.diff" | tail -n 6
      continue
    fi
    grep '^reloc ' "$work/obj/$short/$name.rt.log" >>"$work/obj/$short/coverage.txt"
    ok=$((ok + 1))
  done
  echo "   $short: $ok objects round-trip equal, listing equal but for the string table"
  echo "   $short: relocation coverage (zero counts included)"
  awk '{ count[$2] += $3 } END { for (k in count) print k, count[k] }' "$work/obj/$short/coverage.txt" | sort |
    while read -r kind total; do
      echo "     $kind $total"
    done
done
echo "   $objects_total objects read; $excluded_total excluded (COMDAT groups)"

echo "== 3. mutation proofs"
check_round_trip_hello() {
  build_tools && "$work/bin/obj_elf" "$work/obj/aarch64/hello.o" "$work/mut.o" >"$work/mut-rt.log" 2>&1 &&
    grep -q "^ROUNDTRIP EQUAL" "$work/mut-rt.log"
}
prove_mutation "drop the addend the writer emits for every relocation" "$elf_src" \
  "poke(at + 16_i64, reloc.addend, 8)" "poke(at + 16_i64, 0_i64, 8)" \
  check_round_trip_hello
check_rex_hello() {
  build_tools && "$work/bin/obj_elf" "$work/obj/x86_64/hello.o" "$work/mut.o" >"$work/mut-rt.log" 2>&1 &&
    grep -q "^ROUNDTRIP EQUAL" "$work/mut-rt.log" &&
    diff <(filtered_listing "$work/obj/x86_64/hello.o") <(filtered_listing "$work/mut.o") >/dev/null
}
prove_mutation "read REX_GOTPCRELX as the plain GOTPCRELX kind" "$elf_src" \
  "return 8_i64 if type == 42_i64" "return 7_i64 if type == 42_i64" \
  check_rex_hello
check_linked_structure() {
  build_tools && "$work/bin/link_elf" start "$start_a64_ir" "$work/mut_start.o" >"$work/mut-start.log" 2>&1 &&
    "$work/bin/link_elf" link "$work/mut.exe" _start "$work/mut_start.o" "$work/obj/aarch64/hello.o" >"$work/mut-link.log" 2>&1 &&
    python3 "$check" "$work/mut.exe" --expect-tls >"$work/mut-check.log" 2>&1
}
prove_mutation "skip the relative relocation table entries" "$exe_src" \
  "exe_put(image, @rela_addr + k.to_i64 * 8_i64, rel_sites[k], 8)" "exe_put(image, @rela_addr + k.to_i64 * 8_i64, 0_i64, 8)" \
  check_linked_structure
cp "$work/bin/obj_elf.good" "$work/bin/obj_elf"
cp "$work/bin/link_elf.good" "$work/bin/link_elf"
echo "   listed: the TLS variant offset in the linker (tp_offset) and the relative relocation loop in the start code are"
echo "           seen only by a Linux run (section 6), not by any structural check"

echo "== 4. start code"
for ir in "$start_a64_ir" "$start_x86_ir"; do
  if "$work/bin/link_elf" verify "$ir" >"$work/verify.log" 2>&1; then
    cat "$work/verify.log"
  else
    fail "$ir does not verify:"
    tail -n 5 "$work/verify.log"
  fi
done
if "$work/bin/link_elf" start "$start_a64_ir" "$work/start_a64.o" >"$work/start.log" 2>&1; then
  cat "$work/start.log"
else
  fail "the aarch64 start code does not compile:"
  tail -n 5 "$work/start.log"
fi
iyi_ir="$work/bin/iyi-ir"
if ! "$iyi" build -o "$iyi_ir" src/compiler/tools/ir.iyi >"$work/iyi-ir.build" 2>&1; then
  fail "iyi-ir does not build, the LLVM bridge that translates the start code; its log ends:"
  tail -n 20 "$work/iyi-ir.build" | sed 's/^/     /'
fi
llc_tool="$(command -v llc 2>/dev/null || true)"
[ -n "$llc_tool" ] || fail "llc is not on PATH: the bridged start objects are compiled with it"
# bridge_start IR OBJ: iyi-ir translates the start IR to LLVM IR text, and llc compiles that text to an ELF object.
bridge_start() {
  "$iyi_ir" translate "$1" >"$2.ll" 2>"$2.translate" || return 1
  "$llc_tool" -filetype=obj -relocation-model=pic -o "$2" "$2.ll" >"$2.llc" 2>&1
}
# bridge_check ARCH IR OBJ: bridges IR to OBJ, then links the oracle hello object of ARCH with it and checks the result.
bridge_check() {
  if ! bridge_start "$2" "$3"; then
    fail "$1 start code: the LLVM bridge does not translate and compile it: $(head -n 3 "$3.translate" "$3.llc" 2>/dev/null | tr '\n' ' ')"
    return
  fi
  exe="$work/hello_bridged_$1"
  if "$work/bin/link_elf" link "$exe" _start "$3" "$work/obj/$1/hello.o" >"$exe.link" 2>&1 && python3 "$check" "$exe" --expect-tls >"$exe.check" 2>&1; then
    echo "   $1 start code: iyi-ir translated $(basename "$2") and llc compiled it; it links with the oracle hello and passes the structural check"
  else
    fail "$1 bridged start code does not link with hello: $(head -n 1 "$exe.link" 2>/dev/null)"
  fi
}
if [ -x "$iyi_ir" ] && [ -n "$llc_tool" ]; then
  bridge_check x86_64 "$start_x86_ir" "$work/start_x86_64_bridge.o"
  bridge_check aarch64 "$start_a64_ir" "$work/start_aarch64_bridge.o"
fi

echo "== 5. executables, aarch64: every corpus program links and is checked"
exes=0
for t in $arches; do
  mkdir -p "$work/manifest"
  : >"$work/manifest/$(arch_short "$t")"
done
for triple in $arches; do
  short="$(arch_short "$triple")"
  start="$work/start_a64.o"
  if [ "$short" = x86_64 ]; then
    start="$work/start_x86_64_bridge.o"
  fi
  for obj in "$work/obj/$short"/*.o; do
    case "$obj" in *.rt.o) continue ;; esac
    name="$(basename "$obj" .o)"
    exe="$work/exe/$short/$name"
    mkdir -p "$work/exe/$short"
    if ! "$work/bin/link_elf" link "$exe" _start "$start" "$obj" >"$exe.link" 2>&1; then
      fail "$short $name does not link: $(head -n 1 "$exe.link")"
      continue
    fi
    if ! python3 "$check" "$exe" --expect-tls >"$exe.check" 2>&1; then
      fail "$short $name fails the structural check:"
      sed 's/^/     /' "$exe.check" | tail -n 6
      continue
    fi
    cp "$exe" "$exe.again"
    "$work/bin/link_elf" link "$exe.again" _start "$start" "$obj" >/dev/null 2>&1
    if ! cmp -s "$exe" "$exe.again"; then
      fail "$short $name does not link to identical bytes twice"
      continue
    fi
    exes=$((exes + 1))
    expected=-
    case "$name" in addr_main) expected=random-address ;; esac
    # The flags come last on the line, so that every word of them is read back: on a Linux host the hosted
    # compiler's link line has two (`-rdynamic -fuse-ld=lld`).
    flags="$(oracle_flags "$work/obj/$short/$name.build")"
    [ "$flags" = "-" ] && flags=""
    echo "$name $expected $flags" >>"$work/manifest/$short"
  done
  echo "   $short: executables linked and checked: $(ls "$work/exe/$short" 2>/dev/null | grep -vc '\.' || true)"
done
echo "   $exes executables linked, checked structurally, and linked twice to identical bytes"
echo "   x86_64 executables link against the bridged start object (iyi-ir, then llc); they are never run here"

echo "== 6. runs (Linux only)"
echo "   skipped: needs Linux aarch64 (run each aarch64 executable and compare stdout and exit status with the oracle"
echo "            binary, and run the address-randomisation fixture twice): the native-arm64-linux job runs it"
echo "   skipped: needs Linux x86_64 (sh bench/native_elf_run.sh DIR x86_64 after --emit DIR; the native-linux job's"
echo "            run half)"

echo "== 7. the run half: the emitted set, its manifest, and the run script"
emit="$work/emit"
rm -rf "$emit"
for triple in $arches; do
  short="$(arch_short "$triple")"
  mkdir -p "$emit/$short"
  cp "$work/manifest/$short" "$emit/$short/MANIFEST"
  count=0
  while read -r name expected flags; do
    [ -n "$name" ] || continue
    cp "$work/obj/$short/$name.o" "$emit/$short/$name.o" || fail "$short $name: no oracle object to emit"
    cp "$work/exe/$short/$name" "$emit/$short/$name.native" || fail "$short $name: no native executable to emit"
    if ! python3 "$check" "$emit/$short/$name.native" --expect-tls >/dev/null 2>&1; then
      fail "$short $name: the emitted executable fails the structural check"
    fi
    count=$((count + 1))
  done <"$work/manifest/$short"
  listed="$(sh bench/native_elf_run.sh --list "$emit" "$short" | awk '$1 == "file" { print $2 }' | sort)"
  present="$(find "$emit/$short" -type f | sort)"
  if [ "$listed" = "$present" ]; then
    echo "   $short: $count programs emitted; the file set equals what the run script's --list expects"
  else
    fail "$short: the emitted files differ from what the run script lists:"
    diff <(printf '%s\n' "$listed") <(printf '%s\n' "$present") | sed 's/^/     /' | tail -n 6
  fi
done
if sh -n bench/native_elf_run.sh; then
  echo "   bench/native_elf_run.sh parses under sh -n"
else
  fail "bench/native_elf_run.sh does not parse under sh -n"
fi
if [ -n "$emit_dir" ]; then
  if mkdir -p "$emit_dir" && cp -R "$emit/." "$emit_dir/"; then
    echo "   emitted to $emit_dir"
  else
    fail "cannot write the emit directory $emit_dir"
  fi
fi

if [ "$failures" -eq 0 ]; then
  echo "== ALL NATIVE_ELF CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE_ELF CHECKS FAILED"
exit 1
