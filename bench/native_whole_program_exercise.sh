#!/usr/bin/env bash
# Whole programs through the native back end (SPEC 2.2; the back half of stage 1). The hosted compiler types and
# lowers a program with the real prelude and writes its LLVM IR; iyi-ir imports that into the iyi IR; the native back
# end compiles and links it with no LLVM and no host tool. The program must then run as the hosted executable runs.
# This is the proof that the back end carries a real program (the allocator, fibers, IO, thread-locals), separate
# from whether the front end written in iyi can produce that IR yet.
#
# 1. iyi-compile-native and iyi-ir build from source. The first links libSystem alone. iyi-ir is the bridge that
#    reads LLVM IR and links LLVM by design; it is not part of the native build.
# 2. Every samples/iyi/*.iyi and bench/fixtures/native_whole/*.iyi: the hosted build (executable and IR), the
#    import, the native build under the tripwire (bench/lib/tripwire.sh), both executables run with no stdin for at
#    most 30 seconds, stdout and exit status compared. Each program reaches a phase: import (the import refused it),
#    native (the back end refused it), run (it ran and differs), run-equal. A program the hosted compiler does not
#    build is listed and not counted.
#    Floor: bench/native_whole_program.floor, "<program> <phase>". A phase may only rise; a program below its floor
#    or missing from it fails the gate. NATIVE_WHOLE_PROGRAM_RAISE=1 writes the floor from this run, keeping the
#    higher phase.
# 3. The compiler builds itself in the back half: the tool's own IR is built by the tool (cn1, a compiler with no
#    LLVM in it), cn1 builds the same IR (cn2), and cn1 and cn2 must be the same bytes; cn2 builds hello to the
#    bytes the tool builds it to.
# 4. The tripwire log is empty.
# 5. Mutation proofs on the pieces a whole program needs that no small fixture did.
#
#   bench/native_whole_program_exercise.sh
#
# The native-darwin job runs it through bench/native_gates.sh. Needs a built compiler (`make`) and LLVM for iyi-ir.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
cd "$root" || exit 1
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}

iyi=./bin/iyi
TOOL_SRC=src/compiler/tools/compile_native.iyi
BRIDGE_SRC=src/compiler/tools/ir.iyi
FLOOR=bench/native_whole_program.floor
FIX=bench/fixtures/native_whole

work="$(mktemp -d "${TMPDIR:-/tmp}/native_whole.XXXXXX")" || exit 1
trap 'rm -rf "$work"' EXIT

# shellcheck source=bench/lib/tripwire.sh
. bench/lib/tripwire.sh
# shellcheck source=bench/lib/mutation.sh
. bench/lib/mutation.sh

failures=0
fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

run_bounded() {
  perl -e 'alarm 30; exec @ARGV or exit 127' -- "$1" >"$2" 2>"$3" </dev/null
  echo $?
}

rank_of() {
  case "$1" in
    none) echo 0 ;;
    import) echo 1 ;;
    native) echo 2 ;;
    run) echo 3 ;;
    run-equal) echo 4 ;;
    *) echo -1 ;;
  esac
}

# build_tools DIR: the tool and the bridge from the tree as it is now.
build_tools() {
  mkdir -p "$1"
  "$iyi" build -o "$1/compile_native" "$TOOL_SRC" >"$1/build.tool.log" 2>&1 || return 1
  "$iyi" build -o "$1/iyi-ir" "$BRIDGE_SRC" >"$1/build.bridge.log" 2>&1 || return 1
}

# hosted_of SRC DIR: the hosted executable DIR/hosted and its IR DIR/hosted.ll, with its run recorded.
hosted_of() {
  mkdir -p "$2"
  "$iyi" build --no-debug --emit llvm-ir -o "$2/hosted" "$1" >"$2/hosted.log" 2>&1 || return 1
  [ -f "$2/hosted.ll" ] || return 1
  run_bounded "$2/hosted" "$2/h.out" "$2/h.err" >"$2/h.status"
}

# phase_of TOOLS DIR: imports DIR/hosted.ll, builds it natively and runs it; prints the phase reached and, after a
# tab, the first line of the refusal when there is one.
phase_of() {
  local tools="$1" dir="$2"
  if ! "$tools/iyi-ir" import "$dir/hosted.ll" >"$dir/p.ir" 2>"$dir/import.err"; then
    printf 'import\t%s\n' "$(head -n 1 "$dir/import.err")"
    return
  fi
  if ! PATH="$TRIPWIRE_PATH:$PATH" "$tools/compile_native" "$dir/p.ir" -o "$dir/native" >"$dir/native.log" 2>&1; then
    printf 'native\t%s\n' "$(head -n 1 "$dir/native.log")"
    return
  fi
  local libs
  libs=$(otool -L "$dir/native" | awk 'NR > 1 { print $1 }')
  if [ "$libs" != "/usr/lib/libSystem.B.dylib" ]; then
    printf 'native\tthe executable links %s\n' "$libs"
    return
  fi
  local ns
  ns=$(run_bounded "$dir/native" "$dir/n.out" "$dir/n.err")
  if [ "$ns" = "$(cat "$dir/h.status")" ] && cmp -s "$dir/h.out" "$dir/n.out"; then
    printf 'run-equal\t\n'
  else
    printf 'run\tstatus %s against the hosted %s; first differing line of stdout: %s\n' "$ns" "$(cat "$dir/h.status")" "$(diff "$dir/h.out" "$dir/n.out" | head -n 2 | tail -n 1)"
  fi
}

echo "== 1. build iyi-compile-native and the bridge from source"
tools="$work/tools"
if ! build_tools "$tools"; then
  echo "FAIL: the tools do not build (see $tools)"
  tail -n 20 "$tools"/build.*.log
  exit 1
fi
libs=$(otool -L "$tools/compile_native" | awk 'NR > 1 { print $1 }')
if [ "$libs" = "/usr/lib/libSystem.B.dylib" ]; then
  echo "   iyi-compile-native links only /usr/lib/libSystem.B.dylib"
else
  fail "iyi-compile-native links: $libs"
fi

echo "== 2. every program: hosted IR, import, native build under the tripwire, run, equal to the hosted run"
tripwire_setup "$work/shims" "$work/tripwire.log" || { echo "FAIL: cannot set up the tripwire"; exit 1; }
table="$work/table.txt"
: >"$table"
measured="$work/measured.floor"
: >"$measured"
total=0
equal=0
for src in samples/iyi/*.iyi "$FIX"/*.iyi; do
  [ -f "$src" ] || continue
  n=$(basename "$src" .iyi)
  dir="$work/p/$(dirname "$src" | tr '/' '_')_$n"
  if ! hosted_of "$src" "$dir"; then
    printf '  %-44s HOSTED    the hosted compiler does not build it, or wrote no IR\n' "$src" >>"$table"
    continue
  fi
  total=$((total + 1))
  result=$(phase_of "$tools" "$dir")
  phase=${result%%$'\t'*}
  why=${result#*$'\t'}
  [ "$phase" = "run-equal" ] && equal=$((equal + 1))
  printf '  %-44s %-10s %s\n' "$src" "$phase" "$(printf '%s' "$why" | cut -c1-160)" >>"$table"
  printf '%s %s\n' "$src" "$phase" >>"$measured"
done
cat "$table"
echo "   $equal of $total programs run equal to the hosted executable"

echo "== 2a. the floor"
below=0
if [ "${NATIVE_WHOLE_PROGRAM_RAISE:-0}" = "1" ]; then
  {
    echo "# whole programs through the native back end: <program> <phase reached>. A phase may only rise."
    echo "# Raise with NATIVE_WHOLE_PROGRAM_RAISE=1 bash bench/native_whole_program_exercise.sh (keeps the higher phase)."
    while read -r program phase; do
      old=$(awk -v p="$program" '$1 == p { print $2 }' "$FLOOR" 2>/dev/null)
      if [ -n "$old" ] && [ "$(rank_of "$old")" -gt "$(rank_of "$phase")" ]; then phase=$old; fi
      printf '%s %s\n' "$program" "$phase"
    done <"$measured"
  } >"$work/new.floor"
  cp "$work/new.floor" "$FLOOR"
  echo "   wrote $FLOOR"
fi
while read -r program phase; do
  floor=$(awk -v p="$program" '$1 == p { print $2 }' "$FLOOR" 2>/dev/null)
  if [ -z "$floor" ]; then
    echo "   NO FLOOR: $program reached $phase and has no row in $FLOOR"
    below=$((below + 1))
  elif [ "$(rank_of "$phase")" -lt "$(rank_of "$floor")" ]; then
    echo "   BELOW: $program reached $phase, its floor is $floor"
    below=$((below + 1))
  elif [ "$(rank_of "$phase")" -gt "$(rank_of "$floor")" ]; then
    echo "   RAISE THE FLOOR: $program reached $phase, its floor is $floor"
    below=$((below + 1))
  fi
done <"$measured"
if [ -f "$FLOOR" ]; then
  while read -r program phase; do
    case "$program" in '#'* | '') continue ;; esac
    if ! awk -v p="$program" '$1 == p { found = 1 } END { exit !found }' "$measured"; then
      echo "   GONE: $program has a floor row and was not measured"
      below=$((below + 1))
    fi
  done <"$FLOOR"
fi
if [ "$below" -eq 0 ]; then
  echo "   every program is at its floor"
else
  fail "$below program(s) are off their floor"
fi

echo "== 3. the compiler builds itself in the back half"
self="$work/self"
mkdir -p "$self/a" "$self/b" "$self/h1" "$self/h2"
hello_dir="$work/p/samples_iyi_hello"
if ! "$iyi" build --no-debug --emit llvm-ir -o "$self/hosted" "$TOOL_SRC" >"$self/hosted.log" 2>&1 || [ ! -f "$self/hosted.ll" ]; then
  fail "the hosted compiler wrote no IR for $TOOL_SRC"
elif ! "$tools/iyi-ir" import "$self/hosted.ll" >"$self/cn.ir" 2>"$self/import.err"; then
  fail "the tool's own IR is refused by the import: $(head -n 1 "$self/import.err")"
elif ! PATH="$TRIPWIRE_PATH:$PATH" "$tools/compile_native" "$self/cn.ir" -o "$self/a/cn" >"$self/a.log" 2>&1; then
  fail "the tool does not build its own IR: $(head -n 1 "$self/a.log")"
elif ! PATH="$TRIPWIRE_PATH:$PATH" "$self/a/cn" "$self/cn.ir" -o "$self/b/cn" >"$self/b.log" 2>&1; then
  fail "the natively built tool does not build its own IR: $(head -n 1 "$self/b.log")"
else
  cn_libs=$(otool -L "$self/a/cn" | awk 'NR > 1 { print $1 }')
  [ "$cn_libs" = "/usr/lib/libSystem.B.dylib" ] || fail "the natively built tool links: $cn_libs"
  if cmp -s "$self/a/cn" "$self/b/cn"; then
    echo "   cn1 (built by the tool) and cn2 (built by cn1) are the same $(wc -c <"$self/a/cn" | tr -d ' ') bytes, with no LLVM linked"
  else
    fail "cn1 and cn2 differ: the natively built compiler does not compile as the hosted-built one does"
  fi
  if [ -f "$hello_dir/p.ir" ]; then
    "$tools/compile_native" "$hello_dir/p.ir" -o "$self/h1/hello" >/dev/null 2>&1
    "$self/b/cn" "$hello_dir/p.ir" -o "$self/h2/hello" >/dev/null 2>&1
    if [ -x "$self/h2/hello" ] && cmp -s "$self/h1/hello" "$self/h2/hello"; then
      echo "   cn2 builds hello to the bytes the tool builds it to"
    else
      fail "cn2 does not build hello to the tool's bytes"
    fi
  else
    fail "hello's IR is missing, so cn2 was not exercised"
  fi
fi

echo "== 4. the tripwire"
if tripwire_fired "$work/tripwire.log"; then
  fail "a host tool was run during a native build: $(head -n 3 "$work/tripwire.log")"
else
  echo "   no host tool ran"
fi

echo "== 5. mutation proofs"
# The check rebuilds both tools from the mutated tree and requires the three programs that exercise the mutated
# pieces to still run equal: hello (thread-locals, naked functions, constant expressions, conventions), a result
# wider than the result registers, and a global whose name holds a quote.
whole_still_runs() {
  local t="$work/mut-tools"
  rm -rf "$t"
  build_tools "$t" || return 1
  local src dir result
  for src in samples/iyi/hello.iyi "$FIX/wide_result.iyi" "$FIX/quoted_name.iyi"; do
    dir="$work/p/$(dirname "$src" | tr '/' '_')_$(basename "$src" .iyi)"
    [ -f "$dir/hosted.ll" ] || return 1
    result=$(phase_of "$t" "$dir")
    [ "${result%%$'\t'*}" = "run-equal" ] || return 1
  done
  return 0
}
if ! whole_still_runs; then
  fail "the mutation check does not pass on the unmutated tree, so no mutation was run"
else
  status=0
  prove_mutation "a def imported with the C convention" src/compiler/backend/llvm/import.iyi \
    'return CallConv::Iyi if name.starts_with?("*") || name.starts_with?("~")' \
    'return CallConv::C if name.starts_with?("*") || name.starts_with?("~")' -- whole_still_runs || status=1
  prove_mutation "a constant field address loses its offset" src/compiler/native/const_expr.iyi \
    'off = off + layout.offset_of(cur, n.to_i32)' 'off = off + 0_i64' -- whole_still_runs || status=1
  prove_mutation "a thread-local operand takes the plain symbol address" src/compiler/native/aarch64/isel.iyi \
    'return [thread_local_address(g)] if g.tls != TlsModel::None' \
    'return [symbol_address(g.name, false, false)] if g.tls != TlsModel::None' -- whole_still_runs || status=1
  prove_mutation "a ret after a naked function's template is refused" src/compiler/native/aarch64/isel.iyi \
    '      if i.op == Op::Ret
        lower_ret(i)
        next
      end' '' -- whole_still_runs || status=1
  prove_mutation "a wide internal result is never passed in memory" src/compiler/native/lower.iyi \
    'gprs > desc.integer_args.size || fprs > desc.fp_args.size' 'false' -- whole_still_runs || status=1
  prove_mutation "a quote escaped in a name ends the name" src/compiler/ir/parser.iyi \
    'stop = stop + (line.byte_at(stop) == 92_u8 && stop + 1 < line.bytesize ? 2 : 1)' 'stop = stop + 1' -- whole_still_runs || status=1
  prove_mutation "a numbered parameter is taken as a name" src/compiler/ir/parser.iyi \
    'param_names << (written.numeric ? "" : written.text)' 'param_names << written.text' -- whole_still_runs || status=1
  [ "$status" -eq 0 ] || fail "a mutation was not caught"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "== ALL NATIVE WHOLE PROGRAM CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE WHOLE PROGRAM CHECKS FAILED ($failures)"
exit 1
