#!/usr/bin/env bash
# Runs the native backend's gates, one after another, and prints one verdict
# line per gate. The gates share the checkout (several mutate sources and
# rebuild their tools), so they never run in parallel.
#
#   bash bench/native_gates.sh
#
# The list is written out rather than globbed, because two gates take a target
# and three run programs only an arm64 darwin host can run (the allocator and
# code generator gates build each fixture's twin for the host with aarch64
# inline asm and run it). Those are printed as skipped elsewhere, never as
# passed: the native-darwin job runs them.
#
# Each gate's full output goes to a log under $NATIVE_GATE_LOGS (default: a
# fresh temporary directory). A failing gate's last lines are printed: twelve
# at a desk, where the log is a path away, and $NATIVE_GATE_TAIL (default 200)
# under CI, where the runner is gone and the printed lines are all there is.
# Exit status is 0 only when every gate that ran exits 0.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR="${NATIVE_GATE_LOGS:-$(mktemp -d)}"
mkdir -p "$LOGDIR"
cd "$REPO"

# name | script and arguments | the host it needs ("any" or "darwin-arm64")
gates=(
  "native_ir|bench/native_ir_exercise.sh|any"
  "native_obj|bench/native_obj_exercise.sh|any"
  "native_link|bench/native_link_exercise.sh aarch64-apple-darwin|any"
  "native_encode|bench/native_encode_exercise.sh|any"
  "native_regalloc|bench/native_regalloc_exercise.sh|darwin-arm64"
  "native_asm|bench/native_asm_exercise.sh aarch64|any"
  "native_codegen|bench/native_codegen_exercise.sh|darwin-arm64"
  "native_llvm_roundtrip|bench/native_llvm_roundtrip_exercise.sh|any"
  "native_x86_64|bench/native_x86_64_exercise.sh|any"
  "native_wasm|bench/native_wasm_exercise.sh|any"
  "native_first_light|bench/native_first_light_exercise.sh|darwin-arm64"
)

host="any"
if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
  host="darwin-arm64"
fi

echo "== 1. Running the native gates in order (logs: $LOGDIR)"
status=0
ran=0
failed=()
skipped=()
for entry in "${gates[@]}"; do
  name="${entry%%|*}"
  rest="${entry#*|}"
  command="${rest%%|*}"
  needs="${rest#*|}"
  script="${command%% *}"
  if [ ! -f "$REPO/$script" ]; then
    printf '%-24s missing: %s\n' "$name" "$script"
    status=1
    failed+=("$name")
    continue
  fi
  if [ "$needs" != "any" ] && [ "$needs" != "$host" ]; then
    printf '%-24s skipped: needs a %s host\n' "$name" "$needs"
    skipped+=("$name")
    continue
  fi
  log="$LOGDIR/$name.log"
  # shellcheck disable=SC2086
  bash $command > "$log" 2>&1
  rc=$?
  ran=$((ran + 1))
  printf '%-24s exit=%s\n' "$name" "$rc"
  if [ "$rc" -ne 0 ]; then
    status=1
    failed+=("$name")
    lines=12
    [ -n "${CI:-}" ] && lines="${NATIVE_GATE_TAIL:-200}"
    echo "  last $lines lines of $log:"
    tail -n "$lines" "$log" | sed 's/^/    /'
  fi
done

echo
echo "== 2. Verdicts"
echo "  $((ran - ${#failed[@]}))/$ran gates that ran exited 0; ${#skipped[@]} skipped on this host"
if [ "${#failed[@]}" -gt 0 ]; then
  for name in "${failed[@]}"; do
    echo "  failed: $name"
  done
fi

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL NATIVE GATES PASSED"
else
  echo "== SOME NATIVE GATES FAILED"
fi
exit "$status"
