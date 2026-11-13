#!/usr/bin/env bash
# Runs every bench/selfhost_*_exercise.sh, one after another, and prints one
# verdict line per gate. The gates share the checkout (several mutate sources
# and rebuild the compiler), so they never run in parallel.
#
#   bash bench/selfhost_gates.sh
#   SELFHOST_GATE_SHARD=2/4 bash bench/selfhost_gates.sh
#
# SELFHOST_GATE_SHARD=i/n runs every n-th gate, starting at the i-th of the
# sorted list: n runners, each with its own checkout, cover every gate exactly
# once between them. Without it every gate runs here. Forty-one gates in a row
# were still running when CI's 90 minutes cancelled the Linux job (run
# 43352148795), and every lane adds more.
#
# The typed lowering (src/compiler/lower) targets aarch64-apple-darwin first: its
# thread-local access and its C ABI are that target's, and the end-to-end stage of
# its gates links with the native back end, which builds that target alone. On
# any other host the gates in DARWIN_ARM64_GATES are named as skipped: never run,
# never counted as passed. The darwin arm64 job runs every gate. (The first full
# run of those gates on Linux, run 43365348130, failed each of them on the
# target, not on the port.)
#
# Each gate's full output goes to a log under $SELFHOST_GATE_LOGS (default: a
# fresh temporary directory). A failing gate's last lines are printed: twelve
# at a desk, where the log is a path away, and $SELFHOST_GATE_TAIL (default
# 200) under CI, where the runner is gone and the printed lines are all there is.
# Exit status is 0 only when every gate that ran exits 0.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LOGDIR="${SELFHOST_GATE_LOGS:-$(mktemp -d)}"
mkdir -p "$LOGDIR"
cd "$REPO"

gates=()
for gate in "$REPO"/bench/selfhost_*_exercise.sh; do
  [ -f "$gate" ] && gates+=("$gate")
done
if [ "${#gates[@]}" -eq 0 ]; then
  echo "== 0. no bench/selfhost_*_exercise.sh gates found"
  echo "SOME SELFHOST GATES FAILED"
  exit 1
fi

DARWIN_ARM64_GATES="selfhost_lower_asm_exercise selfhost_lower_calls_exercise selfhost_lower_cast_exercise selfhost_lower_core_exercise selfhost_lower_globals_exercise selfhost_lower_primitives_exercise selfhost_pipeline_exercise"
for listed in $DARWIN_ARM64_GATES; do
  if [ ! -f "$REPO/bench/$listed.sh" ]; then
    echo "== 0. DARWIN_ARM64_GATES names $listed, and bench/$listed.sh is not a gate"
    echo "SOME SELFHOST GATES FAILED"
    exit 1
  fi
done
host="$(uname -s) $(uname -m)"

# 0 when the gate named $1 runs on this host.
runs_here() {
  [ "$host" = "Darwin arm64" ] && return 0
  case " $DARWIN_ARM64_GATES " in
    *" $1 "*) return 1 ;;
  esac
  return 0
}

total="${#gates[@]}"
shard="${SELFHOST_GATE_SHARD:-}"
if [ -n "$shard" ]; then
  index="${shard%%/*}"
  count="${shard##*/}"
  case "$index$count" in
    ''|*[!0-9]*) echo "== 0. SELFHOST_GATE_SHARD is i/n, two numbers, and '$shard' was given"; echo "SOME SELFHOST GATES FAILED"; exit 1 ;;
  esac
  if [ "$shard" != "$index/$count" ] || [ "$count" -lt 1 ] || [ "$index" -lt 1 ] || [ "$index" -gt "$count" ]; then
    echo "== 0. SELFHOST_GATE_SHARD is i/n with 1 <= i <= n, and '$shard' was given"
    echo "SOME SELFHOST GATES FAILED"
    exit 1
  fi
  kept=()
  position=0
  for candidate in "${gates[@]}"; do
    if [ $(( position % count )) -eq $(( index - 1 )) ]; then
      kept+=("$candidate")
    fi
    position=$(( position + 1 ))
  done
  if [ "${#kept[@]}" -eq 0 ]; then
    echo "== 0. shard $shard holds none of the $total gates: fewer gates than shards"
    echo "SOME SELFHOST GATES FAILED"
    exit 1
  fi
  gates=("${kept[@]}")
  echo "== 1. Running shard $shard: ${#gates[@]} of $total selfhost gates in order (logs: $LOGDIR)"
else
  echo "== 1. Running ${#gates[@]} selfhost gates in order (logs: $LOGDIR)"
fi
status=0
failed=()
skipped=()
for gate in "${gates[@]}"; do
  name="$(basename "$gate" .sh)"
  if ! runs_here "$name"; then
    printf '%-44s skipped: needs Darwin arm64, and this host is %s\n' "$name" "$host"
    skipped+=("$name")
    continue
  fi
  log="$LOGDIR/$name.log"
  started=$(date +%s)
  bash "$gate" > "$log" 2>&1
  rc=$?
  printf '%-44s exit=%s seconds=%s\n' "$name" "$rc" "$(( $(date +%s) - started ))"
  if [ "$rc" -ne 0 ]; then
    status=1
    failed+=("$name")
    lines=12
    [ -n "${CI:-}" ] && lines="${SELFHOST_GATE_TAIL:-200}"
    echo "  last $lines lines of $log:"
    tail -n "$lines" "$log" | sed 's/^/    /'
  fi
done

echo
echo "== 2. Verdicts"
ran_count=$(( ${#gates[@]} - ${#skipped[@]} ))
passed_count=$(( ran_count - ${#failed[@]} ))
echo "  $passed_count/$ran_count gates exited 0"
if [ "${#skipped[@]}" -gt 0 ]; then
  echo "  ${#skipped[@]} skipped on this host ($host): they run on Darwin arm64"
fi
if [ "${#failed[@]}" -gt 0 ]; then
  for name in "${failed[@]}"; do
    echo "  failed: $name"
  done
fi

echo
if [ "$status" -eq 0 ] && [ "${#skipped[@]}" -gt 0 ]; then
  echo "== EVERY SELFHOST GATE THAT RUNS ON THIS HOST PASSED (${#skipped[@]} skipped)"
elif [ "$status" -eq 0 ]; then
  echo "== ALL SELFHOST GATES PASSED"
else
  echo "== SOME SELFHOST GATES FAILED"
fi
exit "$status"
