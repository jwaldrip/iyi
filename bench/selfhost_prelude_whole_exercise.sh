#!/usr/bin/env bash
# Proves that the pure iyi self-host compiler tool (iyi-compile) compiles
# the prelude as a whole unit, following all require and import directives,
# measures the compilation phase reached (parse, semantic, codegen, object, link),
# enforces a committed floor against regression, and proves the gate can fail
# under guarded mutation.
#
#   bash bench/selfhost_prelude_whole_exercise.sh
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
export CRYSTAL_CACHE_DIR="${CRYSTAL_CACHE_DIR:-${TMPDIR:-/tmp}/iyi-pwl-cache}"

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
echo "== 2. Measuring whole-prelude compilation phase against committed floor"

# Committed floor for compiling the prelude as a single integrated unit:
# parse -> semantic -> codegen -> object -> link.
# Measured real state: codegen (all 17 prelude modules parse, normalize,
# type check across 53 classes, and codegen emits LLVM IR; object emission
# encounters the known LLVM IR gap documented in STAGE_TWO.md).
WHOLE_FLOOR="codegen"

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

probe_whole_prelude() {
  local target="$REPO/src/iyi/prelude.iyi"
  local log="$WORK/probe_whole_prelude.log"
  set +e
  "$REPO/.build/iyi-compile" --probe-phase "$target" > "$log" 2>&1
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

printf "  %-22s %-10s %-10s %s\n" "Unit" "Floor" "Measured" "Status"
printf "  %-22s %-10s %-10s %s\n" "----------------------" "----------" "----------" "------"

measured_phase="$(probe_whole_prelude)"
measured_rank="$(phase_rank "$measured_phase")"
floor_rank="$(phase_rank "$WHOLE_FLOOR")"

matched=0
total=1
regressions=0

if [ "$measured_rank" -ge "$floor_rank" ]; then
  printf "  %-22s %-10s %-10s %s\n" "prelude (whole)" "$WHOLE_FLOOR" "$measured_phase" "matched"
  matched=$((matched + 1))
else
  printf "  %-22s %-10s %-10s %s\n" "prelude (whole)" "$WHOLE_FLOOR" "$measured_phase" "REGRESSION"
  regressions=$((regressions + 1))
  status=1
fi

echo "  Phase summary: $matched/$total whole-prelude compilation targets match or exceed committed floor ($regressions regressions)"

echo
echo "== 3. Guarded mutation proofs: verifying the gate goes red when whole prelude regresses"

mutations_caught=0
mutations_run=0

# Non-zero (caught) when the whole prelude measures below the committed floor.
check_whole_at_or_above_floor() {
  local floor="$1" measured
  measured="$(probe_whole_prelude)"
  [ "$(phase_rank "$measured")" -ge "$(phase_rank "$floor")" ]
}

# $1 label, $2 prelude file, $3 literal text to patch, $4 its replacement, $5 committed floor.
run_proof() {
  mutations_run=$((mutations_run + 1))
  if prove_mutation "$1" "$REPO/src/iyi/$2" "$3" "$4" -- check_whole_at_or_above_floor "$5"; then
    mutations_caught=$((mutations_caught + 1))
  else
    status=1
  fi
}

run_proof "syntax corruption in prelude regresses below codegen floor" "prelude.iyi" 'require "./primitives"' 'require %%%' "codegen"

run_proof "semantic corruption in prelude regresses below codegen floor" "prelude.iyi" '@proc : Proc(Nil)' '@proc : UndefinedType9876' "codegen"

run_proof "syntax corruption in concurrency regresses whole prelude below codegen floor" "concurrency.iyi" 'class IyiFiber' 'class %%%' "codegen"

run_proof "syntax corruption in primitives regresses whole prelude below codegen floor" "primitives.iyi" 'struct Symbol' 'struct %%%' "codegen"

echo "  Mutation summary: $mutations_caught/$mutations_run regressions caught"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST PRELUDE WHOLE CHECKS PASSED!"
else
  echo "SOME SELFHOST PRELUDE WHOLE CHECKS FAILED"
  exit 1
fi
