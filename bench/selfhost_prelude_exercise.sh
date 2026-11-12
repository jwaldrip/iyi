#!/usr/bin/env bash
# Proves that the pure iyi self-host compiler tool (iyi-compile) compiles
# the real prelude files (src/iyi/*.iyi), measures the compilation phase
# reached by each file (parse, semantic, codegen, object, link), enforces
# a committed floor per file to prevent regressions, and proves the gate can
# fail under guarded mutation.
#
#   bash bench/selfhost_prelude_exercise.sh
#
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

. "$REPO/bench/lib/mutation.sh"

if command -v brew >/dev/null 2>&1; then
  LIBRARY_PATH="$(brew --prefix bdw-gc)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
  export LIBRARY_PATH
fi
export CRYSTAL_CACHE_DIR="${CRYSTAL_CACHE_DIR:-${TMPDIR:-/tmp}/iyi-pdr-cache}"

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
echo "== 2. Measuring prelude compilation phases against committed floor"

# Committed floor per prelude file: measured real state, not assumed.
# 0 = none, 1 = parse, 2 = semantic, 3 = codegen, 4 = object, 5 = link
file_floor() {
  case "$1" in
    "array.iyi")       echo "link" ;;
    "atomic.iyi")      echo "link" ;;
    "concurrency.iyi") echo "link" ;;
    "enum.iyi")        echo "link" ;;
    "file.iyi")        echo "link" ;;
    "float.iyi")       echo "link" ;;
    "hash.iyi")        echo "link" ;;
    "io.iyi")          echo "link" ;;
    "macros.iyi")      echo "link" ;;
    "number.iyi")      echo "link" ;;
    "object.iyi")      echo "link" ;;
    "prelude.iyi")     echo "link" ;;
    "primitives.iyi")  echo "link" ;;
    "range.iyi")       echo "link" ;;
    "set.iyi")         echo "link" ;;
    "string.iyi")      echo "link" ;;
    "thread.iyi")      echo "link" ;;
    *)                 echo "none" ;;
  esac
}

phase_rank() {
  case "$1" in
    none)     echo 0 ;;
    parse)    echo 1 ;;
    semantic) echo 2 ;;
    codegen)  echo 3 ;;
    object)   echo 4 ;;
    link)     echo 5 ;;
    *)        echo -1 ;;
  esac
}

probe_one_file() {
  local target="$1"
  local base
  base="$(basename "$target")"
  local log="$WORK/probe_${base}.log"
  set +e
  "$REPO/.build/iyi-compile" --probe-phase --single-file "$target" > "$log" 2>&1
  set -e
  if grep -qF "[phase] link: pass" "$log"; then
    echo "link"
  elif grep -qF "[phase] object: pass" "$log"; then
    echo "object"
  elif grep -qF "[phase] codegen: pass" "$log"; then
    echo "codegen"
  elif grep -qF "[phase] semantic: pass" "$log"; then
    echo "semantic"
  elif grep -qF "[phase] parse: pass" "$log"; then
    echo "parse"
  else
    echo "none"
  fi
}

printf "  %-18s %-6s %-10s %-10s %s\n" "File" "Lines" "Floor" "Measured" "Status"
printf "  %-18s %-6s %-10s %-10s %s\n" "----------------" "-----" "----------" "----------" "------"

matched=0
total=0
regressions=0

for file_path in "$REPO"/src/iyi/*.iyi; do
  [ -f "$file_path" ] || continue
  total=$((total + 1))
  base="$(basename "$file_path")"
  lines="$(wc -l < "$file_path" | tr -d ' ')"
  floor="$(file_floor "$base")"
  floor_rank="$(phase_rank "$floor")"
  measured="$(probe_one_file "$file_path")"
  measured_rank="$(phase_rank "$measured")"

  if [ "$measured_rank" -lt "$floor_rank" ]; then
    printf "  %-18s %-6s %-10s %-10s %s\n" "$base" "$lines" "$floor" "$measured" "REGRESSION"
    regressions=$((regressions + 1))
    status=1
  elif [ "$measured_rank" -gt "$floor_rank" ]; then
    printf "  %-18s %-6s %-10s %-10s %s\n" "$base" "$lines" "$floor" "$measured" "IMPROVED"
    matched=$((matched + 1))
  else
    printf "  %-18s %-6s %-10s %-10s %s\n" "$base" "$lines" "$floor" "$measured" "matched"
    matched=$((matched + 1))
  fi
done

echo "  Phase summary: $matched/$total prelude files match or exceed committed floor ($regressions regressions)"

echo
echo "== 3. Guarded mutation proofs: verifying the gate goes red when a file regresses"

mutations_caught=0
mutations_run=0

# Non-zero (caught) when the mutated prelude file measures below its committed floor.
check_at_or_above_floor() {
  local target="$1" floor="$2" measured
  measured="$(probe_one_file "$target")"
  [ "$(phase_rank "$measured")" -ge "$(phase_rank "$floor")" ]
}

# $1 label, $2 prelude file, $3 literal text to patch, $4 its replacement, $5 committed floor.
run_proof() {
  mutations_run=$((mutations_run + 1))
  if prove_mutation "$1" "$REPO/src/iyi/$2" "$3" "$4" -- check_at_or_above_floor "$REPO/src/iyi/$2" "$5"; then
    mutations_caught=$((mutations_caught + 1))
  else
    status=1
  fi
}

run_proof "syntax corruption in set regresses below link floor" "set.iyi" 'class Set' 'class %%%' "link"

run_proof "semantic corruption in set regresses below link floor" "set.iyi" '@entries : Hash(T, Bool)' '@entries : UndefinedType12345' "link"

run_proof "syntax corruption in hash regresses below link floor" "hash.iyi" 'class Hash' 'class %%%' "link"

run_proof "syntax corruption in range regresses below link floor" "range.iyi" 'struct Range' 'struct %%%' "link"

run_proof "syntax corruption in enum regresses below link floor" "enum.iyi" 'struct Enum' 'struct %%%' "link"

run_proof "syntax corruption in primitives regresses below link floor" "primitives.iyi" 'struct Symbol' 'struct %%%' "link"

run_proof "syntax corruption in atomic regresses below link floor" "atomic.iyi" 'struct Atomic' 'struct %%%' "link"

run_proof "syntax corruption in prelude regresses below link floor" "prelude.iyi" 'require "./primitives"' 'require %%%' "link"

run_proof "semantic corruption in prelude regresses below link floor" "prelude.iyi" '@proc : Proc(Nil)' '@proc : UndefinedType9876' "link"

run_proof "syntax corruption in concurrency regresses below link floor" "concurrency.iyi" 'class IyiFiber' 'class %%%' "link"

run_proof "syntax corruption in float regresses below link floor" "float.iyi" 'struct Float64' 'struct %%%' "link"

run_proof "syntax corruption in array regresses below link floor" "array.iyi" 'class Array' 'class %%%' "link"

run_proof "syntax corruption in file regresses below link floor" "file.iyi" 'class File' 'class %%%' "link"

run_proof "syntax corruption in string regresses below link floor" "string.iyi" 'class String' 'class %%%' "link"

run_proof "syntax corruption in number regresses below link floor" "number.iyi" 'struct Int32' 'struct %%%' "link"

run_proof "syntax corruption in object regresses below link floor" "object.iyi" 'class Object' 'class %%%' "link"

run_proof "syntax corruption in io regresses below link floor" "io.iyi" 'class IyiIO' 'class %%%' "link"
echo "  Mutation summary: $mutations_caught/$mutations_run regressions caught"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST PRELUDE CHECKS PASSED!"
else
  echo "SOME SELFHOST PRELUDE CHECKS FAILED"
  exit 1
fi
