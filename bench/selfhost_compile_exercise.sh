#!/usr/bin/env bash
# Proves that the pure iyi self-host compiler tool (iyi-compile) compiles whole
# programs end-to-end using ONLY the ported compiler stages:
#   1. Parser (compiler/syntax/parser)
#   2. Semantic Analysis (compiler/semantic/top_level, compiler/semantic/main_visitor)
#   3. LLVM Code Generation (compiler/codegen/codegen, compiler/llvm)
#   4. Target & Linker (compiler/platform/target, compiler/platform/linker)
#
# Compares execution exit codes, output, and dependency floors against the
# shipped compiler across all compile fixtures.
#
#   bash bench/selfhost_compile_exercise.sh
#
set -u
status=0
diverged=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
COMPILE_TOOL_SRC="$REPO/src/compiler/tools/compile.iyi"
COMPILER_SRC="$REPO/src/compiler/compiler.iyi"
LOADER_SRC="$REPO/src/compiler/loader.iyi"
CODEGEN_SRC="$REPO/src/compiler/codegen/codegen.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

if command -v brew >/dev/null 2>&1; then
  LIBRARY_PATH="$(brew --prefix bdw-gc 2>/dev/null)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
  export LIBRARY_PATH
fi
export CRYSTAL_CACHE_DIR="${TMPDIR:-/tmp}/iyi-s2-cache"

echo "== 1. Building self-host compile tool"
cd "$REPO"
rm -f "$REPO/.build/iyi-compile"
make iyi-compile

if [ ! -x "$REPO/.build/iyi-compile" ]; then
  echo "  ERROR: .build/iyi-compile was not built"
  exit 1
fi
echo "  built .build/iyi-compile successfully"

echo
echo "== 2. Whole program execution parity: pure iyi compiler vs shipped compiler"
FIXTURES=(
  "bench/fixtures/compile_exit.iyi"
  "bench/fixtures/compile_arith.iyi"
  "bench/fixtures/compile_control.iyi"
  "bench/fixtures/compile_loop.iyi"
  "bench/fixtures/compile_struct.iyi"
  "bench/fixtures/compile_class.iyi"
  "bench/fixtures/compile_pointers.iyi"
  "bench/fixtures/compile_multi_import.iyi"
  "bench/fixtures/compile_diamond.iyi"
  "bench/fixtures/compile_top_level.iyi"
  "bench/fixtures/compile_no_top_level.iyi"
  "bench/fixtures/compile_cross_const.iyi"
  "bench/fixtures/compile_reopen_class.iyi"
  "bench/fixtures/compile_raise.iyi"
  "bench/fixtures/compile_stdout.iyi"
)

matched=0
total=${#FIXTURES[@]}

for fixture in "${FIXTURES[@]}"; do
  base="$(basename "$fixture" .iyi)"
  iyi_bin="$WORK/iyi_${base}"
  cr_bin="$WORK/cr_${base}"

  if ! "$REPO/.build/iyi-compile" -o "$iyi_bin" "$fixture" > "$WORK/compile_iyi_${base}.log" 2>&1; then
    echo "  FAIL: pure iyi compiler failed to compile $fixture"
    cat "$WORK/compile_iyi_${base}.log"
    status=1
    continue
  fi

  if ! "$IYI" build --prelude=empty -o "$cr_bin" "$fixture" > "$WORK/compile_cr_${base}.log" 2>&1; then
    echo "  FAIL: shipped compiler failed to compile $fixture"
    cat "$WORK/compile_cr_${base}.log"
    status=1
    continue
  fi

  set +e
  "$iyi_bin" > "$WORK/out_iyi_${base}.txt" 2> "$WORK/err_iyi_${base}.txt"
  iyi_rc=$?
  "$cr_bin" > "$WORK/out_cr_${base}.txt" 2> "$WORK/err_cr_${base}.txt"
  cr_rc=$?
  set -e

  if [ "$iyi_rc" -eq "$cr_rc" ] && cmp -s "$WORK/out_iyi_${base}.txt" "$WORK/out_cr_${base}.txt"; then
    echo "  $fixture: identical execution exit code (rc=$iyi_rc) and stdout"
    matched=$((matched + 1))
  else
    echo "  FAIL: $fixture execution diverged: iyi rc=$iyi_rc, crystal rc=$cr_rc"
    diff -u "$WORK/out_cr_${base}.txt" "$WORK/out_iyi_${base}.txt" || true
    status=1
  fi
done
# The shipped compiler's stdout for compile_stdout is the oracle for the stdout proof.
cp "$WORK/out_cr_compile_stdout.txt" "$WORK/oracle_stdout.txt" 2>/dev/null || touch "$WORK/oracle_stdout.txt"
echo "  Parity summary: $matched/$total compile fixtures match 100% across execution"

echo
echo "== 3. Dependency floor verification: pure iyi compiler produces dependency-floor binaries"
floor_matched=0
for fixture in "${FIXTURES[@]}"; do
  base="$(basename "$fixture" .iyi)"
  iyi_bin="$WORK/iyi_${base}"
  [ -x "$iyi_bin" ] || continue

  # Verify binary does not link libgc, and links the platform C library.
  case "$(uname -s)" in
    Darwin)
      if ! command -v otool >/dev/null 2>&1; then
        echo "  FAIL: otool not found; the dependency floor of $base cannot be measured"
        status=1
        continue
      fi
      libs="$(otool -L "$iyi_bin" | grep -v ":" | awk '{print $1}' | tr '\n' ' ')"
      if echo "$libs" | grep -qF "libgc"; then
        echo "  FAIL: $base links libgc: $libs"
        status=1
        continue
      fi
      if ! echo "$libs" | grep -qF "libSystem.B.dylib"; then
        echo "  FAIL: $base does not link libSystem: $libs"
        status=1
        continue
      fi
      ;;
    Linux)
      if ! command -v readelf >/dev/null 2>&1; then
        echo "  FAIL: readelf not found; the dependency floor of $base cannot be measured"
        status=1
        continue
      fi
      needed="$(readelf -d "$iyi_bin" | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' | tr '\n' ' ')"
      if echo "$needed" | grep -qF "libgc"; then
        echo "  FAIL: $base links libgc: $needed"
        status=1
        continue
      fi
      if ! echo "$needed" | grep -qF "libc.so.6"; then
        echo "  FAIL: $base does not link libc.so.6: $needed"
        status=1
        continue
      fi
      ;;
    *)
      echo "  FAIL: the dependency floor is measured on Darwin and Linux only, not on $(uname -s)"
      status=1
      continue
      ;;
  esac
  floor_matched=$((floor_matched + 1))
done
echo "  Dependency floor summary: $floor_matched/$total binaries link only platform libc (no libgc)"

echo
echo "== 4. Object emission without linking (--emit-obj)"
"$REPO/.build/iyi-compile" --emit-obj "$WORK/test_emit.o" "$REPO/bench/fixtures/compile_exit.iyi" > "$WORK/emit_obj.log" 2>&1
if [ -f "$WORK/test_emit.o" ] && [ -s "$WORK/test_emit.o" ]; then
  echo "  --emit-obj successfully wrote object file: $WORK/test_emit.o"
else
  echo "  FAIL: --emit-obj did not produce object file"
  status=1
fi

echo
echo "== 5. Malformed input and error refusal checks"
refusals=0
# 1. Syntax error properly refused
set +e
"$REPO/.build/iyi-compile" -o "$WORK/bad1" <(echo "fun main : Int32; (1 + ; end") > "$WORK/err1.log" 2>&1
rc1=$?
set -e
if [ "$rc1" -ne 0 ]; then
  echo "  properly refused: malformed syntax rejected (rc=$rc1)"
  refusals=$((refusals + 1))
else
  echo "  FAIL: malformed syntax was not refused"
  status=1
fi

# 2. Missing input file properly refused
set +e
"$REPO/.build/iyi-compile" -o "$WORK/bad2" "non_existent_file_12345.iyi" > "$WORK/err2.log" 2>&1
rc2=$?
set -e
if [ "$rc2" -ne 0 ]; then
  echo "  properly refused: missing input file rejected (rc=$rc2)"
  refusals=$((refusals + 1))
else
  echo "  FAIL: missing file was not refused"
  status=1
fi

# 3. Missing import properly refused with identical message and exit code to shipped compiler
set +e
"$IYI" build --prelude=empty -o "$WORK/shipped_bad3" "$REPO/bench/fixtures/compile_missing_import.iyi" > "$WORK/shipped_missing.log" 2>&1
shipped_rc=$?
"$REPO/.build/iyi-compile" -o "$WORK/bad3" "$REPO/bench/fixtures/compile_missing_import.iyi" > "$WORK/selfhost_missing.log" 2>&1
selfhost_rc=$?
set -e
if [ "$selfhost_rc" -eq "$shipped_rc" ] && [ "$selfhost_rc" -ne 0 ] && \
   grep -q "can't find module 'nonexistent/missing_mod'" "$WORK/selfhost_missing.log" && \
   grep -q "can't find module 'nonexistent/missing_mod'" "$WORK/shipped_missing.log"; then
  echo "  properly refused: missing import rejected with identical exit code (rc=$selfhost_rc) and message"
  refusals=$((refusals + 1))
else
  echo "  FAIL: missing import was not properly refused"
  status=1
fi

# 4. Undefined type inside a generic class refused, as the shipped compiler does.
# A pass that skipped generic classes made this compile cleanly while the shipped
# compiler rejected it, so the refusal is compared rather than assumed.
set +e
"$IYI" build --no-codegen "$REPO/bench/fixtures/compile_undefined_type.iyi" > "$WORK/shipped_undef.log" 2>&1
shipped_undef_rc=$?
"$REPO/.build/iyi-compile" -o "$WORK/bad4" "$REPO/bench/fixtures/compile_undefined_type.iyi" > "$WORK/selfhost_undef.log" 2>&1
selfhost_undef_rc=$?
set -e
if [ "$selfhost_undef_rc" -ne 0 ] && [ "$shipped_undef_rc" -ne 0 ] && \
   grep -q "UndefinedTypeInGeneric" "$WORK/selfhost_undef.log"; then
  echo "  properly refused: undefined type in a generic class rejected (rc=$selfhost_undef_rc), as the shipped compiler does (rc=$shipped_undef_rc)"
  refusals=$((refusals + 1))
else
  echo "  FAIL: undefined type in a generic class was not refused (iyi rc=$selfhost_undef_rc, shipped rc=$shipped_undef_rc)"
  status=1
fi
echo "  Refusal summary: $refusals/4 malformed scenarios refused properly"

echo
echo "== 6. Guarded mutation proofs"

# Rebuilds the pure compiler from the sources as they are now, then compiles the
# fixture and requires the program's exit code to equal the expected one.
check_compile_rc() {
  local fixture="$1" expected="$2" mut_rc=0
  rm -f "$REPO/.build/iyi-compile"
  make -C "$REPO" iyi-compile >/dev/null 2>&1 || return 1
  "$REPO/.build/iyi-compile" -o "$WORK/mut_bin" "$fixture" >/dev/null 2>&1 || return 1
  "$WORK/mut_bin" >/dev/null 2>&1 || mut_rc=$?
  [ "$mut_rc" -eq "$expected" ]
}

# Compiles the (mutated) fixture with the already built compiler and requires the
# program's exit code to equal the expected one.
check_fixture_rc() {
  local fixture="$1" expected="$2" mut_rc=0
  "$REPO/.build/iyi-compile" -o "$WORK/mut_bin_fx" "$fixture" >/dev/null 2>&1 || return 1
  "$WORK/mut_bin_fx" >/dev/null 2>&1 || mut_rc=$?
  [ "$mut_rc" -eq "$expected" ]
}

# Compiles the (mutated) fixture and requires its stdout to equal the stdout the
# shipped compiler's binary printed for the unmutated fixture.
check_stdout_parity() {
  local fixture="$1" oracle="$2"
  "$REPO/.build/iyi-compile" -o "$WORK/mut_bin_out" "$fixture" >/dev/null 2>&1 || return 1
  "$WORK/mut_bin_out" > "$WORK/mut_stdout.txt" 2>/dev/null || true
  cmp -s "$WORK/mut_stdout.txt" "$oracle"
}

# A mutation of a compiler source leaves .build/iyi-compile built from the mutated
# source, so rebuild it from the restored source before any later check uses it.
rebuild_clean_compile() {
  rm -f "$REPO/.build/iyi-compile"
  if ! make -C "$REPO" iyi-compile >/dev/null 2>&1; then
    echo "  ERROR: could not rebuild the clean compiler after a mutation"
    status=1
  fi
}

mutate_compiler_source() {
  prove_mutation "$@" || status=1
  rebuild_clean_compile
}

mutate_compiler_source "corrupt linker placeholder substitution" \
  "$COMPILER_SRC" \
  '"\"${@}\""' \
  '"__WRONG_PLACEHOLDER__"' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_arith.iyi" 26

mutate_compiler_source "corrupt object file output path" \
  "$COMPILER_SRC" \
  'obj_path = @config.obj_output_filename || (@config.output_filename + ".o")' \
  'obj_path = @config.obj_output_filename || "/nonexistent/dir/out.o"' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_arith.iyi" 26

prove_mutation "corrupt arithmetic operation in test fixture" \
  "$REPO/bench/fixtures/compile_arith.iyi" \
  'v1 &- v2' \
  'v1 &+ v2' \
  -- check_fixture_rc "$REPO/bench/fixtures/compile_arith.iyi" 26 || status=1

mutate_compiler_source "wrong resolver resolution order" \
  "$LOADER_SRC" \
  '@order << clean_fn' \
  '@order = [clean_fn] + @order' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_diamond.iyi" 52

mutate_compiler_source "missed import in resolver" \
  "$LOADER_SRC" \
  'resolve_file(clean_res, clean_fn)' \
  '# resolve_file(clean_res, clean_fn)' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_diamond.iyi" 52

mutate_compiler_source "omitting entry point wrapper for top-level code" \
  "$CODEGEN_SRC" \
  '  return if top_level_stmts.empty?' \
  '  return if true' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_top_level.iyi" 42

mutate_compiler_source "pipeline drops top-level statements" \
  "$COMPILER_SRC" \
  'append_entry_point(funs, top_level)' \
  '# append_entry_point(funs, top_level)' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_top_level.iyi" 42

mutate_compiler_source "pipeline drops default entry point for declaration-only program" \
  "$COMPILER_SRC" \
  'top_level << Nop.new' \
  '# top_level << Nop.new' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_no_top_level.iyi" 0

prove_mutation "corrupt runtime __crystal_raise entry point" \
  "$REPO/bench/fixtures/compile_raise.iyi" \
  'p64[4] = ex.address' \
  'p64[4] = 0_u64' \
  -- check_fixture_rc "$REPO/bench/fixtures/compile_raise.iyi" 38 || status=1

prove_mutation "corrupt runtime __crystal_personality entry point" \
  "$REPO/bench/fixtures/compile_raise.iyi" \
  'return 6' \
  'return 8' \
  -- check_fixture_rc "$REPO/bench/fixtures/compile_raise.iyi" 38 || status=1

prove_mutation "corrupt runtime __crystal_get_exception entry point" \
  "$REPO/bench/fixtures/compile_raise.iyi" \
  'p64[4]' \
  'p64[0]' \
  -- check_fixture_rc "$REPO/bench/fixtures/compile_raise.iyi" 38 || status=1

mutate_compiler_source "pipeline supplies raise runtime when missing" \
  "$COMPILER_SRC" \
  'Compiler.append_raise_runtime(classes, funs, defs, libs, top_level)' \
  '# Compiler.append_raise_runtime(classes, funs, defs, libs, top_level)' \
  -- check_compile_rc "$REPO/bench/fixtures/compile_implicit_raise.iyi" 42

# A stdout difference must fail the stdout parity. The shipped compiler's stdout
# for the unmutated fixture is the oracle; the mutation prints a different letter.
prove_mutation "a stdout difference fails the stdout parity check" \
  "$REPO/bench/fixtures/compile_stdout.iyi" \
  'LibC.putchar(107)' \
  'LibC.putchar(108)' \
  -- check_stdout_parity "$REPO/bench/fixtures/compile_stdout.iyi" "$WORK/oracle_stdout.txt" || status=1
echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST COMPILE CHECKS PASSED!"
else
  echo "SOME SELFHOST COMPILE CHECKS FAILED"
  exit 1
fi
