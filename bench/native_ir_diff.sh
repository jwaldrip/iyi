#!/usr/bin/env bash
# Compare the same iyi IR via LLVM and the native object backend on darwin-arm64.
# Usage: bash bench/native_ir_diff.sh [FILE.ir ...]
# With no arguments, generates 200 deterministic seeds and runs the native_cg
# fixture list. Set NATIVE_DIFF_DIR to retain all inputs, logs and outputs;
# NATIVE_DIFF_BRIDGE / NATIVE_DIFF_CG can point at already-built drivers.
# Both binaries link the same runtime stand-in and C identity function.
set -u
cd "$(dirname "$0")/.." || exit 1
[ "$(uname -s):$(uname -m)" = Darwin:arm64 ] || { printf 'requires darwin-arm64\n' >&2; exit 1; }
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
if [ -n "${NATIVE_DIFF_DIR:-}" ]; then
  work=$NATIVE_DIFF_DIR
  mkdir -p "$work"
  work=$(cd "$work" && pwd)
else
  work=$(mktemp -d "${TMPDIR:-/tmp}/native-diff.XXXXXX") || exit 1
  trap 'rm -rf "$work"' EXIT
fi
bridge=${NATIVE_DIFF_BRIDGE:-$work/iyi-ir}
cg=${NATIVE_DIFF_CG:-$work/native_cg}
if [ -z "${NATIVE_DIFF_BRIDGE:-}" ]; then
  ./bin/iyi build -o "$bridge" src/compiler/tools/ir.iyi >"$work/build-bridge.log" 2>&1 || { printf 'bridge build failed: %s\n' "$work/build-bridge.log"; exit 1; }
fi
if [ -z "${NATIVE_DIFF_CG:-}" ]; then
  ./bin/iyi build -o "$cg" src/compiler/tools/native_cg.iyi >"$work/build-cg.log" 2>&1 || { printf 'native object driver build failed: %s\n' "$work/build-cg.log"; exit 1; }
fi
python3 bench/gen_narrow_ir.py "$work/generated" 200 || exit 1
if [ "$#" -eq 0 ]; then
  set -- bench/fixtures/native_cg/rmw.ir bench/fixtures/native_cg/narrow_cmpxchg.ir bench/fixtures/native_cg/narrow_switch.ir bench/fixtures/native_cg/narrow_call.ir bench/fixtures/native_cg/narrow_i1.ir bench/fixtures/native_cg/narrow_param.ir "$work"/generated/seed_*.ir
fi
: >"$work/report.txt"
index=0; passed=0; failed=0
for ir in "$@"; do
  index=$((index + 1)); dir="$work/case-$index"; mkdir -p "$dir"
  printf '%s\n' "$ir" >"$dir/input.txt"
  if ! "$bridge" translate "$ir" >"$dir/input.ll" 2>"$dir/translate.err"; then
    printf 'FAIL translate %s (%s)\n' "$ir" "$dir" | tee -a "$work/report.txt"; failed=$((failed + 1)); continue
  fi
  if ! llc -O0 -filetype=obj -mtriple=arm64-apple-macosx "$dir/input.ll" -o "$dir/llvm.o" >"$dir/llc.log" 2>&1; then
    printf 'FAIL llc %s (%s)\n' "$ir" "$dir" | tee -a "$work/report.txt"; failed=$((failed + 1)); continue
  fi
  if ! "$cg" obj "$ir" "$dir/native.o" >"$dir/native.log" 2>&1; then
    printf 'FAIL native-object %s (%s)\n' "$ir" "$dir" | tee -a "$work/report.txt"; failed=$((failed + 1)); continue
  fi
  if ! cc "$dir/llvm.o" bench/fixtures/native_cg/rt_stub.c "$work/generated/identity.c" -o "$dir/llvm" >"$dir/llvm-link.log" 2>&1 || ! cc "$dir/native.o" bench/fixtures/native_cg/rt_stub.c "$work/generated/identity.c" -o "$dir/native" >"$dir/native-link.log" 2>&1; then
    printf 'FAIL link %s (%s)\n' "$ir" "$dir" | tee -a "$work/report.txt"; failed=$((failed + 1)); continue
  fi
  if ! codesign -v --strict "$dir/llvm" >"$dir/llvm-sign.log" 2>&1 || ! codesign -v --strict "$dir/native" >"$dir/native-sign.log" 2>&1; then
    printf 'FAIL signature %s (%s)\n' "$ir" "$dir" | tee -a "$work/report.txt"; failed=$((failed + 1)); continue
  fi
  perl -e 'alarm 30; exec @ARGV or exit 127' -- "$dir/llvm" >"$dir/llvm.out" 2>"$dir/llvm.err" </dev/null; ls=$?
  perl -e 'alarm 30; exec @ARGV or exit 127' -- "$dir/native" >"$dir/native.out" 2>"$dir/native.err" </dev/null; ns=$?
  printf '%s\n' "$ls" >"$dir/llvm.status"; printf '%s\n' "$ns" >"$dir/native.status"
  if [ "$ls" = "$ns" ] && cmp -s "$dir/llvm.out" "$dir/native.out"; then
    passed=$((passed + 1)); printf 'PASS %s\n' "$ir" >>"$work/report.txt"
  else
    failed=$((failed + 1)); printf 'DIFFER %s llvm=%s native=%s (%s)\n' "$ir" "$ls" "$ns" "$dir" | tee -a "$work/report.txt"
  fi
done
printf 'IR differential: %s passed, %s failed, %s total; report %s/report.txt\n' "$passed" "$failed" "$index" "$work"
[ "$failed" -eq 0 ] && [ "$index" -gt 0 ]
