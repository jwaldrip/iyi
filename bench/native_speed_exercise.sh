#!/usr/bin/env bash
# Compare the self-hosted native backend with the hosted LLVM compiler.
# NATIVE_SPEED_RUNS sets the number of interleaved runtime rounds (default 5).
# NATIVE_SPEED_TOLERANCE_SCALE overrides the pull-request noise multiplier.
# NATIVE_SPEED_LATENCY=1 runs the self-build and stage2/stage3 identity check.
# NATIVE_SPEED_TARGET=1 checks every runtime and latency row against 1.00.
# NATIVE_SPEED_LOWER=1 lowers measured ceilings, or proposes them in CI.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1
REPO=$(pwd -P)
. "$REPO/bench/lib/host.sh" || exit 1
require_test_host || exit 1
[ -n "$PY" ] || { echo "FAIL: a working Python interpreter is required" >&2; exit 1; }
. "$REPO/bench/lib/mutation.sh" || exit 1
export IYI_PATH="$(native_path "$REPO/src")"
unset IYI_OPTS IYI_NATIVE_REGALLOC
if [ "$HOST_OS" = darwin ]; then
  export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:"$PATH"
  export LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/native-speed.XXXXXX") || exit 1
trap 'rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
LOGDIR=${SELFHOST_GATE_LOGS:-"$WORK"}
mkdir -p "$LOGDIR" || exit 1
HELPER="$REPO/bench/lib/native_speed.py"
FIX="$REPO/bench/fixtures/native_speed"
CEILING="$REPO/bench/native_speed.ceiling"
IYI="$REPO/bin/iyi"
STAGE1="$WORK/iyi-stage1"
SOURCE="$REPO/src/compiler/stage1.iyi"
RUNS=${NATIVE_SPEED_RUNS:-5}
SCALE=${NATIVE_SPEED_TOLERANCE_SCALE:-}
if [ -z "$SCALE" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then SCALE=2; else SCALE=1; fi
fi
failed=0
fail() { echo "FAIL: $*"; failed=1; }

case "$RUNS" in
  ''|*[!0-9]*) fail "NATIVE_SPEED_RUNS must be a positive integer"; RUNS=5 ;;
  *)
    RUNS="${RUNS#"${RUNS%%[!0]*}"}"
    if [ -z "$RUNS" ]; then fail "NATIVE_SPEED_RUNS must be a positive integer"; RUNS=5; fi
    ;;
esac

# Fixture checks return 1 only for a wrong verdict; setup failures return 2.
check_judge_fixtures() {
  local fixture rc
  for fixture in "$FIX"/judge/pass_*.json "$FIX"/judge/fail_*.json; do
    [ -f "$fixture" ] || return 2
    rc=0
    "$PY" "$(native_path "$HELPER")" judge --fixture "$(native_path "$fixture")" >"$WORK/fixture.log" 2>&1 || rc=$?
    if [ "$rc" -eq 1 ]; then cat "$WORK/fixture.log"; return 1; fi
    if [ "$rc" -ne 0 ]; then cat "$WORK/fixture.log"; return 2; fi
  done
  return 0
}

check_writer() {
  local fixture="$FIX/judge/writer_raise.json"
  "$PY" - "$(native_path "$fixture")" "$(native_path "$WORK/writer.ceiling")" <<'PY' || return 2
import json, pathlib, sys
fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
pathlib.Path(sys.argv[2]).write_text(fixture["ceiling"], encoding="utf-8")
PY
  "$PY" "$(native_path "$HELPER")" lower --ceiling "$(native_path "$WORK/writer.ceiling")" \
    --measurements "$(native_path "$fixture")" --write "$(native_path "$WORK/writer.out")" || return 2
  "$PY" - "$(native_path "$fixture")" "$(native_path "$WORK/writer.out")" <<'PY'
import json, pathlib, sys
fixture = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
lines = [line.split() for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()]
rows = [row for row in lines if row[:3] == ["arith", "default", "cycles"]]
if len(rows) != 1 or len(rows[0]) != 4:
    sys.exit(2)
if rows[0][3] != fixture["expect"]:
    print("decisive: the writer changed the 1.20 ceiling to " + rows[0][3])
    sys.exit(1)
PY
}

build() {
  local compiler="$1" src="$2" output="$3" log="$4"
  shift 4
  mkdir -p "$(dirname "$output")" || return 1
  "$compiler" build "$@" -o "$(native_path "$output")" "$(native_path "$src")" >"$log" 2>&1
}

merge_measurements() {
  "$PY" - "$@" <<'PY'
import json, pathlib, sys
out, *inputs = sys.argv[1:]
rows = []
for name in inputs:
    rows.extend(json.loads(pathlib.Path(name).read_text(encoding="utf-8"))["rows"])
pathlib.Path(out).write_text(json.dumps({"rows": rows}, indent=2) + "\n", encoding="utf-8")
PY
}

# A mutation is decisive only when a measured ratio crosses its ceiling, not
# when a build, a result comparison or the noise check fails.
check_pinned_allocator() {
  local mut="$WORK/pin" name rc
  [ -f "$WORK/runtime.json" ] || return 2
  mkdir -p "$mut"
  "$PY" - "$WORK/runtime.json" "$mut/baseline.json" <<'PY' || return 2
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
rows = [row for row in data["rows"] if row["mode"] == "default" and row["workload"] in ("arith", "fannkuch")]
if len(rows) != 2:
    sys.exit(2)
pathlib.Path(sys.argv[2]).write_text(json.dumps({"rows": rows}), encoding="utf-8")
PY
  if ! NATIVE_SPEED_LOWER=0 "$PY" "$HELPER" judge --ceiling "$CEILING" --measurements "$mut/baseline.json" --scale 1 >"$mut/baseline.log" 2>&1; then
    cat "$mut/baseline.log"
    return 2
  fi
  if ! build "$IYI" "$SOURCE" "$mut/iyi-stage1" "$mut/stage1.log" --release; then cat "$mut/stage1.log"; return 2; fi
  : >"$mut/pairs.tsv"
  for name in arith fannkuch; do
    if ! build "$mut/iyi-stage1" "$FIX/workloads/$name.iyi" "$mut/$name/a.out" "$mut/$name.log"; then cat "$mut/$name.log"; return 2; fi
    printf '%s\tdefault\t%s\t%s\n' "$name" "$WORK/hosted-default/$name/a.out" "$mut/$name/a.out" >>"$mut/pairs.tsv"
  done
  "$PY" "$HELPER" measure --pairs "$mut/pairs.tsv" --runs 3 --timeout 300 --out "$mut/measure.json" || return 2
  rc=0
  NATIVE_SPEED_LOWER=0 "$PY" "$HELPER" judge --ceiling "$CEILING" --measurements "$mut/measure.json" \
    --scale 1 --tsv "$mut/report.tsv" >"$mut/judge.log" 2>&1 || rc=$?
  cat "$mut/judge.log"
  [ "$rc" -eq 0 ] && return 0
  [ "$rc" -eq 1 ] || return 2
  if awk -F '\t' 'NR > 1 { if ($12 == "FAIL") bad++; else if ($12 != "PASS") invalid++ } END { exit !(bad > 0 && invalid == 0) }' "$mut/report.tsv"; then
    echo "decisive: the pinned allocator exceeded a committed ceiling"
    return 1
  fi
  return 2
}

check_wrong_code() {
  local mut="$WORK/wrong-code"
  [ -x "$WORK/hosted-default/arith/a.out" ] || return 2
  mkdir -p "$mut"
  if ! build "$IYI" "$SOURCE" "$mut/iyi-stage1" "$mut/stage1.log" --release; then cat "$mut/stage1.log"; return 2; fi
  if ! build "$mut/iyi-stage1" "$FIX/workloads/arith.iyi" "$mut/arith/a.out" "$mut/arith.log"; then cat "$mut/arith.log"; return 2; fi
  "$PY" - "$WORK/hosted-default/arith/a.out" "$mut/arith/a.out" <<'PY'
import re, subprocess, sys
try:
    hosted = subprocess.run([sys.argv[1]], capture_output=True, text=True, timeout=300)
    if hosted.returncode != 0:
        sys.exit(2)
    expected = re.findall(r"(?m)^result=(.*)$", hosted.stdout)
    if len(expected) != 1:
        sys.exit(2)
    try:
        native = subprocess.run([sys.argv[2]], capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        print("decisive: mutated program timed out")
        sys.exit(1)
    actual = re.findall(r"(?m)^result=(.*)$", native.stdout)
    if native.returncode != 0 or actual != expected:
        print("decisive: mutated program failed or produced a different result")
        sys.exit(1)
except (OSError, subprocess.TimeoutExpired):
    sys.exit(2)
PY
}

echo "== 1. judge fixtures and ceiling writer"
fixture_rc=0
check_judge_fixtures || fixture_rc=$?
if [ "$fixture_rc" -ne 0 ]; then fail "judge fixtures failed (exit $fixture_rc)"; fi
writer_rc=0
check_writer || writer_rc=$?
if [ "$writer_rc" -ne 0 ]; then fail "ceiling writer failed (exit $writer_rc)"; fi
if [ "$fixture_rc" -eq 0 ] && [ "$writer_rc" -eq 0 ]; then echo "  judge and writer fixtures passed"; fi

echo "== 2. build the self-hosted compiler"
stage1_ok=0
if [ "$HOST_ID" = darwin-arm64 ]; then
  if build "$IYI" "$SOURCE" "$STAGE1" "$WORK/stage1.log" --release; then
    stage1_ok=1
    echo "  built iyi-stage1 with hosted --release"
  else
    fail "hosted compiler could not build iyi-stage1"
    tail -n 40 "$WORK/stage1.log"
  fi
else
  host_limited "native speed builds require macOS arm64"
fi

echo "== 3. build both modes and check that native --release changes code"
builds_ok=0
native_release=unknown
if [ "$HOST_ID" = darwin-arm64 ] && [ "$stage1_ok" -eq 1 ]; then
  builds_ok=1
  : >"$WORK/pairs.tsv"
  for name in arith nbody fannkuch trees escape hash append; do
    src="$FIX/workloads/$name.iyi"
    hdefault="$WORK/hosted-default/$name/a.out"
    hrelease="$WORK/hosted-release/$name/a.out"
    ndefault="$WORK/native-default/$name/a.out"
    nrelease="$WORK/native-release/$name/a.out"
    if ! build "$IYI" "$src" "$hdefault" "$WORK/$name.hosted-default.log"; then
      fail "hosted default build failed for $name"; tail -n 20 "$WORK/$name.hosted-default.log"; builds_ok=0
    fi
    if ! build "$IYI" "$src" "$hrelease" "$WORK/$name.hosted-release.log" --release; then
      fail "hosted release build failed for $name"; tail -n 20 "$WORK/$name.hosted-release.log"; builds_ok=0
    fi
    if ! build "$STAGE1" "$src" "$ndefault" "$WORK/$name.native-default.log"; then
      fail "native default build failed for $name"; tail -n 20 "$WORK/$name.native-default.log"; builds_ok=0
    fi
    if [ "$native_release" = unknown ] || [ "$native_release" = yes ]; then
      if build "$STAGE1" "$src" "$nrelease" "$WORK/$name.native-release.log" --release; then
        native_release=yes
        if [ -f "$ndefault" ] && cmp -s "$ndefault" "$nrelease"; then
          fail "--release changes nothing for $name"
        fi
      elif [ "$native_release" = unknown ] && grep -Fxq -- 'Error: --release is not in the self-hosted compiler yet' "$WORK/$name.native-release.log"; then
        native_release=no
        echo "  native --release is not in the self-hosted compiler yet; release rows use native default"
      else
        fail "native release build failed for $name"; tail -n 20 "$WORK/$name.native-release.log"; builds_ok=0
        native_release=failed
      fi
    fi
    if [ "$native_release" = no ]; then nrelease="$ndefault"; fi
    printf '%s\tdefault\t%s\t%s\n' "$name" "$hdefault" "$ndefault" >>"$WORK/pairs.tsv"
    printf '%s\trelease\t%s\t%s\n' "$name" "$hrelease" "$nrelease" >>"$WORK/pairs.tsv"
  done
elif [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited "native speed workload builds and release comparison require macOS arm64"
fi

echo "== 4. runtime measurements"
runtime_ok=0
if [ "$HOST_ID" = darwin-arm64 ] && [ "$builds_ok" -eq 1 ] && [ "$failed" -eq 0 ]; then
  if "$PY" "$HELPER" measure --pairs "$WORK/pairs.tsv" --runs "$RUNS" --timeout 300 --out "$WORK/runtime.json"; then
    runtime_ok=1
    "$PY" "$HELPER" judge --ceiling "$CEILING" --measurements "$WORK/runtime.json" --scale "$SCALE" \
      --tsv "$WORK/runtime.tsv" || fail "runtime verdicts failed"
    cp "$WORK/runtime.tsv" "$LOGDIR/native_speed.tsv" || fail "could not write native_speed.tsv"
  else
    fail "runtime measurement failed"
  fi
elif [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited "native speed runtime measurements require macOS arm64"
fi

target=0
if [ "${NATIVE_SPEED_TARGET:-0}" = 1 ] || grep -Eq '^[[:space:]]*NATIVE_TARGETS[[:space:]]*=[[:space:]]*\[[^]]*"aarch64-apple-darwin"' "$REPO/src/compiler/backend/backend.iyi"; then target=1; fi

echo "== 5. compiler latency and stage2/stage3 identity"
latency_ok=0
stage2_ok=0
do_latency=0
if [ "${NATIVE_SPEED_LATENCY:-0}" = 1 ] || [ "$target" -eq 1 ]; then
  do_latency=1
elif [ "$HOST_ID" = darwin-arm64 ] && [ "${GITHUB_EVENT_NAME:-}" != pull_request ]; then
  mem=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
  case "$mem" in ''|*[!0-9]*) mem=0 ;; esac
  [ "$mem" -lt 17179869184 ] || do_latency=1
fi
if [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited "latency arm and compiler bootstrap require macOS arm64"
elif [ "$do_latency" -eq 0 ]; then
  host_limited "latency arm requires NATIVE_SPEED_LATENCY=1 or a non-pull-request host with at least 16 GiB"
elif [ "$stage1_ok" -eq 1 ] && [ "$native_release" != unknown ] && [ "$native_release" != failed ]; then
  mkdir -p "$WORK/s2" "$WORK/s3"
  if [ "$native_release" = yes ]; then
    if build "$STAGE1" "$SOURCE" "$WORK/s2/iyi" "$WORK/s2.log" --release; then stage2_ok=1; fi
  else
    if build "$STAGE1" "$SOURCE" "$WORK/s2/iyi" "$WORK/s2.log"; then stage2_ok=1; fi
  fi
  if [ "$stage2_ok" -ne 1 ]; then
    fail "stage2 build failed"; tail -n 40 "$WORK/s2.log"
  else
    stage3_ok=0
    if [ "$native_release" = yes ]; then
      if build "$WORK/s2/iyi" "$SOURCE" "$WORK/s3/iyi" "$WORK/s3.log" --release; then stage3_ok=1; fi
    else
      if build "$WORK/s2/iyi" "$SOURCE" "$WORK/s3/iyi" "$WORK/s3.log"; then stage3_ok=1; fi
    fi
    if [ "$stage3_ok" -ne 1 ]; then
      fail "stage3 build failed"; tail -n 40 "$WORK/s3.log"
    elif cmp -s "$WORK/s2/iyi" "$WORK/s3/iyi"; then
      echo "  stage2 and stage3 are byte-identical"
    else
      fail "stage2 and stage3 differ"
    fi
    if "$PY" "$HELPER" latency --old "$STAGE1" --new "$WORK/s2/iyi" --source "$SOURCE" --runs 3 --out "$WORK/latency.json"; then
      latency_ok=1
      "$PY" "$HELPER" judge --ceiling "$CEILING" --measurements "$WORK/latency.json" --scale "$SCALE" \
        --tsv "$WORK/latency.tsv" || fail "latency verdicts failed"
      if [ -f "$LOGDIR/native_speed.tsv" ]; then
        tail -n +2 "$WORK/latency.tsv" >>"$LOGDIR/native_speed.tsv" || fail "could not append latency rows"
      fi
    else
      fail "latency measurement failed"
    fi
  fi
else
  fail "latency arm needs a working stage1 and release probe"
fi

echo "== 6. target check"
if [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited "native speed target check requires macOS arm64"
elif [ "$target" -eq 0 ]; then
  echo "  native target not selected"
elif [ "$runtime_ok" -eq 1 ] && [ "$latency_ok" -eq 1 ]; then
  target_runs=$((RUNS * 2))
  if "$PY" "$HELPER" measure --pairs "$WORK/pairs.tsv" --runs "$target_runs" --timeout 300 --out "$WORK/target-runtime.json" \
    && "$PY" "$HELPER" latency --old "$STAGE1" --new "$WORK/s2/iyi" --source "$SOURCE" --runs "$target_runs" --out "$WORK/target-latency.json" \
    && merge_measurements "$WORK/target.json" "$WORK/target-runtime.json" "$WORK/target-latency.json"; then
    "$PY" "$HELPER" judge --ceiling "$CEILING" --measurements "$WORK/target.json" --scale 1 --target || fail "target check failed"
  else
    fail "target check could not measure every runtime and latency row"
  fi
else
  fail "target check needs runtime and latency measurements"
fi

echo "== 7. mutation proofs"
if [ "$HOST_ID" = darwin-arm64 ]; then
  prove_mutation "pinned allocator regresses runtime" "$REPO/src/compiler/native/regalloc.iyi" \
    $'  if choice.nil?\n    return true' $'  if choice.nil?\n    return false' -- check_pinned_allocator || fail "allocator mutation was not proven"
  prove_mutation "wrong signed comparison changes the result" "$REPO/src/compiler/native/aarch64/isel.iyi" \
    $'  elsif ordinal == 8_i64\n    return cond_lt' $'  elsif ordinal == 8_i64\n    return cond_le' -- check_wrong_code || fail "wrong-code mutation was not proven"
else
  host_limited "allocator and wrong-code mutation proofs require macOS arm64"
fi
prove_mutation "judge detects an exceeded ceiling" "$HELPER" 'if ratio > bound:' 'if False:' -- check_judge_fixtures || fail "judge mutation was not proven"
prove_mutation "writer cannot raise a ceiling" "$HELPER" 'kept = min(old, measured)' 'kept = measured' -- check_writer || fail "writer mutation was not proven"

echo "== 8. ceiling ratchet"
if [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited "native speed ratchet needs macOS arm64 measurements"
elif [ "$runtime_ok" -eq 1 ]; then
  if [ "$latency_ok" -eq 1 ]; then
    merge_measurements "$WORK/all.json" "$WORK/runtime.json" "$WORK/latency.json" || fail "could not combine measurements"
  else
    cp "$WORK/runtime.json" "$WORK/all.json" || fail "could not preserve measurements"
  fi
  if [ -f "$WORK/all.json" ] && { [ -n "${CI:-}" ] || [ "${NATIVE_SPEED_LOWER:-0}" = 1 ]; }; then
    if [ -n "${CI:-}" ]; then
      destination="$LOGDIR/native_speed.ceiling.proposed"
    else
      destination="$CEILING"
    fi
    if "$PY" "$HELPER" lower --ceiling "$CEILING" --measurements "$WORK/all.json" --write "$WORK/ceiling.new"; then
      cp "$WORK/ceiling.new" "$destination" || fail "could not write $destination"
      echo "  wrote $destination"
    else
      fail "ceiling ratchet refused the measurements"
    fi
  else
    echo "  ceiling unchanged"
  fi
else
  echo "  no runtime measurements to ratchet"
fi

if [ "$failed" -eq 0 ]; then
  echo "ALL NATIVE SPEED CHECKS PASSED!"
  exit 0
fi
echo "SOME NATIVE SPEED CHECKS FAILED"
exit 1
