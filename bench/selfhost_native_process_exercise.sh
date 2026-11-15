#!/usr/bin/env bash
# Exercise Process.run through hosted and native stage-one entry paths.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
export IYI_PATH="$REPO/src"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"
fixture="$REPO/bench/fixtures/native_process_run.iyi"
probe="$REPO/bench/fixtures/spawnshare_process.iyi"

run_monitored() {
  if [ -n "${IYI_MEMORY_MONITOR:-}" ]; then
    "$IYI_MEMORY_MONITOR" "$@"
  else
    "$@"
  fi
}

run_timed() {
  python3 - "$@" <<'PY'
import os, signal, subprocess, sys
seconds = int(sys.argv[1])
proc = subprocess.Popen(sys.argv[2:], start_new_session=True)
try:
    status = proc.wait(timeout=seconds)
except subprocess.TimeoutExpired:
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
    print('FAIL: process timed out', file=sys.stderr)
    sys.exit(124)
sys.exit(status if status >= 0 else 128 - status)
PY
}

if ! run_monitored "$IYI" build -o "$WORK/hosted" "$fixture" > "$WORK/hosted.build" 2>&1; then
  echo 'FAIL: hosted process fixture did not build'; cat "$WORK/hosted.build"; exit 1
fi
if ! run_timed 120 "$WORK/hosted" > "$WORK/hosted.out" 2> "$WORK/hosted.err"; then
  echo 'FAIL: hosted process fixture'; cat "$WORK/hosted.out" "$WORK/hosted.err"; exit 1
fi
if ! run_monitored "$IYI" build -o "$WORK/stage1" "$REPO/src/compiler/stage1.iyi" > "$WORK/stage1.build" 2>&1; then
  echo 'FAIL: stage1 did not build'; cat "$WORK/stage1.build"; exit 1
fi
if ! run_monitored "$WORK/stage1" build -o "$WORK/probe" "$probe" > "$WORK/probe.build" 2>&1; then
  echo 'FAIL: native process probe did not build'; cat "$WORK/probe.build"; exit 1
fi
if ! codesign -v --strict "$WORK/probe"; then
  echo 'FAIL: native probe signature'; exit 1
fi
if ! run_timed 120 "$WORK/probe" > "$WORK/probe.out" 2> "$WORK/probe.err" ||
   [ "$(cat "$WORK/probe.out")" != 'process-ok:parent-ok' ]; then
  echo 'FAIL: native process probe'; cat "$WORK/probe.out" "$WORK/probe.err"; exit 1
fi
if ! run_monitored "$WORK/stage1" build -o "$WORK/native" "$fixture" > "$WORK/native.build" 2>&1; then
  echo 'FAIL: native process fixture did not build'; cat "$WORK/native.build"; exit 1
fi
if ! codesign -v --strict "$WORK/native"; then
  echo 'FAIL: native fixture signature'; exit 1
fi
if ! run_timed 120 "$WORK/native" > "$WORK/native.out" 2> "$WORK/native.err" ||
   ! cmp -s "$WORK/hosted.out" "$WORK/native.out" ||
   ! cmp -s "$WORK/hosted.err" "$WORK/native.err"; then
  echo 'FAIL: native process output differs'; cat "$WORK/native.out" "$WORK/native.err"; exit 1
fi
if ! run_monitored "$WORK/stage1" run "$fixture" > "$WORK/run.out" 2> "$WORK/run.err" ||
   ! cmp -s "$WORK/hosted.out" "$WORK/run.out"; then
  echo 'FAIL: stage1 run differs'; cat "$WORK/run.out" "$WORK/run.err"; exit 1
fi

# A build error in the mutated compiler is invalid. A catch requires that it
# builds, then rejects the exact process spawn previously shown to compile.
check_cast_mutation() {
  if ! run_monitored "$IYI" build -o "$WORK/mutant-stage1" "$REPO/src/compiler/stage1.iyi" > "$WORK/mutant.build" 2>&1; then
    echo 'INVALID: mutant stage1 did not build'; cat "$WORK/mutant.build"; return 0
  fi
  run_monitored "$WORK/mutant-stage1" build -o "$WORK/mutant-probe" "$probe" > "$WORK/mutant.log" 2>&1
  local rc=$?
  local site
  site="$(grep -n 'g\.spawn.*\.as(String | Cancelled)' "$REPO/src/std/process.iyi" | cut -d: -f1)"
  if [ "$rc" -ne 0 ] && [ -n "$site" ] &&
     grep -E "spawn classification of .*std/process\\.iyi:${site}:[0-9]+ is not ported" "$WORK/mutant.log" >/dev/null; then
    echo 'mutant stage1 compiled and refused the cast spawn'
    return 1
  fi
  echo 'INVALID: cast mutant did not produce the expected refusal'; cat "$WORK/mutant.log"
  return 0
}
prove_mutation 'cast operand is not traversed' "$REPO/src/compiler/semantic/spawn_placement.iyi" \
  '    elsif node.is_a?(Cast)
      walk(node.as(Cast).obj)' '' -- check_cast_mutation || exit 1
printf '%s\n' 'native Process.run matches hosted, including cancellation; mutation caught'
