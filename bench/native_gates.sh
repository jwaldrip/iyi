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

host="any"
if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
  host="darwin-arm64"
fi

status=0
ran=0
failed=()
skipped=()

# run_gate NAME HOST SCRIPT [ARGUMENT...]: HOST is "any" or "darwin-arm64".
# Each gate is a line that runs its script, which is what
# bench/gates_reachable.py reads to know the gate is run.
run_gate() {
  local name="$1" needs="$2" script="$3"
  shift 2
  if [ ! -f "$REPO/$script" ]; then
    printf '%-24s missing: %s\n' "$name" "$script"
    status=1
    failed+=("$name")
    return
  fi
  if [ "$needs" != "any" ] && [ "$needs" != "$host" ]; then
    printf '%-24s skipped: needs a %s host\n' "$name" "$needs"
    skipped+=("$name")
    return
  fi
  local log="$LOGDIR/$name.log"
  bash "$@" > "$log" 2>&1
  local rc=$?
  ran=$((ran + 1))
  printf '%-24s exit=%s\n' "$name" "$rc"
  if [ "$rc" -ne 0 ]; then
    status=1
    failed+=("$name")
    local lines=12
    [ -n "${CI:-}" ] && lines="${NATIVE_GATE_TAIL:-200}"
    echo "  last $lines lines of $log:"
    tail -n "$lines" "$log" | sed 's/^/    /'
  fi
}

echo "== 1. Running the native gates in order (logs: $LOGDIR)"
run_gate native_ir any bench/native_ir_exercise.sh

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
