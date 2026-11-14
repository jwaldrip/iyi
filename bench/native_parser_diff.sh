#!/usr/bin/env bash
# Compare the parser and AST dumper built through hosted LLVM and the IR bridge.
# Usage: NATIVE_PARSER_DIFF_DIR=/path/to/report bash bench/native_parser_diff.sh
# Every .iyi under src, samples/iyi and bench/fixtures is tested, including
# malformed inputs. Stdout, stderr and exit status are compared separately.
# Set NATIVE_PARSER_STAGE1 to a native compiler to add the typed pipeline;
# a typed build refusal is recorded as SKIP rather than mistaken for a pass.
# Reports and the differing input's outputs are kept in NATIVE_PARSER_DIFF_DIR.
set -u
cd "$(dirname "$0")/.." || exit 1
[ "$(uname -s):$(uname -m)" = Darwin:arm64 ] || { printf 'requires darwin-arm64\n' >&2; exit 1; }
export PATH="/opt/homebrew/opt/llvm/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
work=${NATIVE_PARSER_DIFF_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/parser-diff.XXXXXX")}
mkdir -p "$work"; work=$(cd "$work" && pwd)
bridge=${NATIVE_DIFF_BRIDGE:-$work/iyi-ir}
compiler=${NATIVE_PARSER_COMPILER:-$work/compile_native}
: >"$work/report.txt"
if [ -z "${NATIVE_DIFF_BRIDGE:-}" ]; then
  ./bin/iyi build -o "$bridge" src/compiler/tools/ir.iyi >"$work/build-bridge.log" 2>&1 || { printf 'bridge build failed: %s\n' "$work/build-bridge.log"; exit 1; }
fi
if [ -z "${NATIVE_PARSER_COMPILER:-}" ]; then
  ./bin/iyi build -o "$compiler" src/compiler/tools/compile_native.iyi >"$work/build-compiler.log" 2>&1 || { printf 'compiler build failed: %s\n' "$work/build-compiler.log"; exit 1; }
fi
fail=0
for pair in 'parser:src/compiler/tools/parse.iyi' 'exercise:bench/selfhost_parser_exercise.iyi'; do
  name=${pair%%:*}; src=${pair#*:}; dir="$work/$name"; mkdir -p "$dir"
  if ! ./bin/iyi build --no-debug --verbose --emit llvm-ir -o "$dir/hosted" "$src" >"$dir/hosted-build.log" 2>&1; then
    printf 'FAIL %s hosted build (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; fail=1; continue
  fi
  if ! "$bridge" import "$dir/hosted.ll" >"$dir/program.ir" 2>"$dir/import.err"; then
    printf 'FAIL %s import (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; fail=1; continue
  fi
  awk '{for (i=1;i<NF;i++) if ($i == "-framework") print $(i+1)}' "$dir/hosted-build.log" | sort -u >"$dir/frameworks"
  if [ -s "$dir/frameworks" ]; then cp "$dir/frameworks" "$dir/program.ir.imports"; fi
  if ! "$compiler" "$dir/program.ir" -o "$dir/bridge" >"$dir/bridge-build.log" 2>&1; then
    printf 'FAIL %s bridge build (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; fail=1; continue
  fi
  if ! codesign -v --strict "$dir/bridge" >"$dir/bridge-sign.log" 2>&1; then
    printf 'FAIL %s bridge signature (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; fail=1; continue
  fi
  typed=0
  if [ -n "${NATIVE_PARSER_STAGE1:-}" ]; then
    if ! codesign -v --strict "$NATIVE_PARSER_STAGE1" >"$dir/stage1-sign.log" 2>&1; then
      printf 'FAIL stage1 signature (%s)\n' "$dir" | tee -a "$work/report.txt"; fail=1
    elif "$NATIVE_PARSER_STAGE1" "$src" -o "$dir/typed" --pipeline typed --prelude >"$dir/typed-build.log" 2>&1; then
      if codesign -v --strict "$dir/typed" >"$dir/typed-sign.log" 2>&1; then typed=1; else fail=1; printf 'FAIL %s typed signature\n' "$name" | tee -a "$work/report.txt"; fi
    else
      printf 'SKIP %s typed build refused (%s)\n' "$name" "$dir/typed-build.log" | tee -a "$work/report.txt"
    fi
  else
    printf 'SKIP %s typed: NATIVE_PARSER_STAGE1 not set\n' "$name" | tee -a "$work/report.txt"
  fi
  find src samples/iyi bench/fixtures -type f -name '*.iyi' -print | LC_ALL=C sort >"$dir/corpus.txt"
  [ "$name" = exercise ] && printf '\n' >>"$dir/corpus.txt"
  n=0; equal=0; different=0
  while IFS= read -r file; do
    n=$((n+1)); case_dir="$dir/case-$n"; mkdir -p "$case_dir"
    printf '%s\n' "$file" >"$case_dir/input.txt"
    args=(); [ -n "$file" ] && args=("$file")
    for impl in hosted bridge; do
      if [ "$impl" = bridge ] && ! codesign -v --strict "$dir/bridge" >"$dir/bridge-sign.log" 2>&1; then
        printf 'FAIL %s bridge signature (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; exit 1
      fi
      perl -e 'alarm 30; exec @ARGV or exit 127' -- "$dir/$impl" "${args[@]}" >"$case_dir/$impl.out" 2>"$case_dir/$impl.err" </dev/null
      printf '%s\n' "$?" >"$case_dir/$impl.status"
    done
    if [ "$( <"$case_dir/hosted.status")" != 142 ] && [ "$( <"$case_dir/bridge.status")" != 142 ] && cmp -s "$case_dir/hosted.status" "$case_dir/bridge.status" && cmp -s "$case_dir/hosted.out" "$case_dir/bridge.out" && cmp -s "$case_dir/hosted.err" "$case_dir/bridge.err"; then
      equal=$((equal+1))
    else
      different=$((different+1)); fail=1
      printf 'DIFFER %s %s (%s)\n' "$name" "${file:-<no-argument>}" "$case_dir" | tee -a "$work/report.txt"
    fi
    if [ "$typed" -eq 1 ]; then
      if ! codesign -v --strict "$dir/typed" >"$dir/typed-sign.log" 2>&1; then
        printf 'FAIL %s typed signature (%s)\n' "$name" "$dir" | tee -a "$work/report.txt"; exit 1
      fi
      perl -e 'alarm 30; exec @ARGV or exit 127' -- "$dir/typed" "${args[@]}" >"$case_dir/typed.out" 2>"$case_dir/typed.err" </dev/null
      printf '%s\n' "$?" >"$case_dir/typed.status"
      if [ "$( <"$case_dir/typed.status")" = 142 ] || ! cmp -s "$case_dir/hosted.status" "$case_dir/typed.status" || ! cmp -s "$case_dir/hosted.out" "$case_dir/typed.out" || ! cmp -s "$case_dir/hosted.err" "$case_dir/typed.err"; then
        fail=1; printf 'DIFFER typed %s %s (%s)\n' "$name" "${file:-<no-argument>}" "$case_dir" | tee -a "$work/report.txt"
      fi
    fi
  done <"$dir/corpus.txt"
  printf '%s: %s equal, %s different, %s total\n' "$name" "$equal" "$different" "$n" | tee -a "$work/report.txt"
done
printf 'report: %s/report.txt\n' "$work"
exit "$fail"
