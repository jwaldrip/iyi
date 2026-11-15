#!/usr/bin/env bash
# Prove refusal rows reach the sidecar while body typing is still running.
set -eu
repo="$(cd "$(dirname "$0")/.." && pwd)"
compiler="${STREAM_COMPILER:?set STREAM_COMPILER to the native compile_native executable}"
baseline="${STREAM_BASELINE:?set STREAM_BASELINE to the pre-change native compiler}"
codesign -v --strict "$compiler"
codesign -v --strict "$baseline"
work="$(mktemp -d)"
child=""
cleanup() {
  if [ -n "$child" ]; then kill "$child" 2>/dev/null || true; wait "$child" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM
export IYI_PATH="$repo/src"
fixture="$repo/bench/fixtures/pipeline_streamed_refusal.iyi"
for kind in baseline current; do
  bin="$baseline"
  [ "$kind" = current ] && bin="$compiler"
  "$bin" "$fixture" -o "$work/$kind" --pipeline typed --prelude --probe-phase --keep-going >"$work/$kind.log" 2>&1 || true
  awk '/^table: / {print}' "$work/$kind.log" > "$work/$kind.table"
done
cmp "$work/baseline.table" "$work/current.table"
cmp "$work/baseline.refusals" "$work/current.refusals"
# A large independent tail keeps the process in body typing after the first refusal.
cp "$fixture" "$work/stream_tail.iyi"
for ((i=0; i<12000; i++)); do printf 'value_%d = %d\n' "$i" "$i" >> "$work/stream_tail.iyi"; done
"$compiler" "$work/stream_tail.iyi" -o "$work/stream" --pipeline typed --prelude --probe-phase --keep-going >"$work/stream.log" 2>&1 &
child=$!
seen=0
for ((i=0; i<1200; i++)); do
  if [ -s "$work/stream.refusals" ]; then
    kill -0 "$child" 2>/dev/null || { echo 'stream was written only after exit' >&2; exit 1; }
    if grep -q 'missing_streamed_method' "$work/stream.refusals"; then seen=1; break; fi
  fi
  kill -0 "$child" 2>/dev/null || { echo 'compiler exited before the first streamed refusal' >&2; exit 1; }
  sleep 0.05
done
[ "$seen" -eq 1 ] || { echo 'streamed refusal did not arrive' >&2; exit 1; }
kill "$child"; wait "$child" 2>/dev/null || true; child=""
grep -q '^record[[:space:]]' "$work/stream.refusals"
grep -q 'streaming_example' "$work/stream.refusals"
grep -q 'stream_tail.iyi:2:' "$work/stream.refusals"
echo 'streamed refusal visible before exit; completed tables and sidecars unchanged'
