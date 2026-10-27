#!/usr/bin/env bash
# Exercises `std/observe`.
#
#     bash bench/std_observe_exercise.sh
#
# Proves:
#   * The exercise holds plain and --release.
#   * With IYI_OBSERVE set, direct observer calls write expected bytes (hexdump
#     assertion; on Windows, which records its paths in its own form and whose
#     observation runtime nothing else here measures, the trace is only
#     required to end with END(0)).
#   * Normal end writes END(0).
#   * A panic writes END(1) and nothing else.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="${IYI:-$REPO/bin/iyi}"
WORK="$(mktemp -d)"

trap 'rm -rf "$WORK"' EXIT

WINDOWS=0
case "$(uname -s)" in
  MINGW* | MSYS* | CYGWIN* | Windows_NT)
    PSEP=';'
    WINDOWS=1
    REPO="$(cygpath -m "$REPO")"
    WORK="$(cygpath -m "$WORK")"
    ;;
  *) PSEP=':' ;;
esac

export IYI_PATH="$REPO/src${PSEP}$REPO/samples/iyi"

u32_le_hex() {
  local val=$1
  printf '%02x%02x%02x%02x' $(( val & 0xff )) $(( (val >> 8) & 0xff )) $(( (val >> 16) & 0xff )) $(( (val >> 24) & 0xff ))
}

echo "== plain build and run"
"$IYI" build -o "$WORK/exercise" "$REPO/bench/std_observe_exercise.iyi"
"$WORK/exercise"

echo "== release build and run"
"$IYI" build --release -o "$WORK/exercise_rel" "$REPO/bench/std_observe_exercise.iyi"
"$WORK/exercise_rel"

echo "== observation build with IYI_OBSERVE and hexdump assertion"
TRACE_FILE="$WORK/trace.bin"
rm -f "$TRACE_FILE"
# From `/`, so the cwd record (the real current directory) is the same in
# every checkout.
SCRATCH_DIR="$WORK/scratch"
mkdir -p "$SCRATCH_DIR"
SCRATCH_REAL="$(cd "$SCRATCH_DIR" && pwd -P)"
WRITE_PATH="${SCRATCH_REAL}/out.txt"
(cd / && TMPDIR="$SCRATCH_REAL" IYI_OBSERVE="$TRACE_FILE" "$IYI" run -Diyi_observe "$REPO/bench/std_observe_exercise.iyi")

if [ ! -f "$TRACE_FILE" ]; then
  echo "FAIL: trace file was not created"
  exit 1
fi

if [ "$WINDOWS" = 1 ]; then
  echo "  hexdump assertion skipped on Windows; the trace ends with END(0) below"
else
  ACTUAL_HEX="$(od -An -v -tx1 "$TRACE_FILE" | tr -d ' \n')"
  EXPECTED_HEX="1900000003000000000000000003000000464f4f01030000006261720009000000040000000000000000"
  EXPECTED_HEX="${EXPECTED_HEX}0e00000005000000000000000001000000"'2f'"1600000006000000000000000009000000746573742d686f7374"
  # Program.env("TMPDIR") reads TMPDIR from environment; observe runtime records value as "scratch"
  EXPECTED_HEX="${EXPECTED_HEX}2000000003000000000000000006000000544d5044495201070000007363726174636800"
  # Dynamic file_write record for WRITE_PATH under scratch
  WRITE_PATH_HEX="$(printf '%s' "$WRITE_PATH" | od -An -v -tx1 | tr -d ' \n')"
  WRITE_PATH_LEN=${#WRITE_PATH}
  WRITE_REC_LEN=$(( 19 + WRITE_PATH_LEN ))
  WRITE_REC_LEN_HEX="$(u32_le_hex $WRITE_REC_LEN)"
  WRITE_PATH_LEN_HEX="$(u32_le_hex $WRITE_PATH_LEN)"
  EXPECTED_HEX="${EXPECTED_HEX}${WRITE_REC_LEN_HEX}07000000000000000001${WRITE_PATH_LEN_HEX}${WRITE_PATH_HEX}0000000001"
  # The first clock taint:
  EXPECTED_HEX="${EXPECTED_HEX}1d000000080000000000000000200f0000007372633a746573742e6979693a3130"
  # The second clock taint is dropped; the entropy taint is its kind's first.
  EXPECTED_HEX="${EXPECTED_HEX}1d000000080000000000000000210f0000007372633a746573742e6979693a3132"
  EXPECTED_HEX="${EXPECTED_HEX}0d0000007f000000000000000000000000"

  if [ "$ACTUAL_HEX" != "$EXPECTED_HEX" ]; then
    echo "FAIL: trace hex mismatch"
    echo "  expected: $EXPECTED_HEX"
    echo "  actual:   $ACTUAL_HEX"
    exit 1
  fi
  echo "  hexdump assertion passed ($(( ${#EXPECTED_HEX} / 2 )) bytes matched exactly)"
fi

echo "== normal end writes END(0)"
# Last 17 bytes must be: 0d 00 00 00 7f 00 00 00 00 00 00 00 00 00 00 00 00
TAIL_HEX="$(tail -c 17 "$TRACE_FILE" | od -An -v -tx1 | tr -d ' \n')"
EXPECTED_TAIL="0d0000007f000000000000000000000000"
if [ "$TAIL_HEX" != "$EXPECTED_TAIL" ]; then
  echo "FAIL: expected END(0) at end of trace, got $TAIL_HEX"
  exit 1
fi
echo "  END(0) verified"

echo "== panic writes END(1)"
# A panic leaves through __iyi_exit(1), so the trace ends with END(1); only a
# signal death or a timeout kill leaves no END.
PANIC_TRACE="$WORK/panic_trace.bin"
cat << 'EOF' > "$WORK/panic_prog.iyi"
raise "intentional panic for observation test"
EOF

rm -f "$PANIC_TRACE"
if IYI_OBSERVE="$PANIC_TRACE" "$IYI" run -Diyi_observe "$WORK/panic_prog.iyi" >/dev/null 2>&1; then
  echo "FAIL: panic program was expected to exit nonzero"
  exit 1
fi

PANIC_HEX="$(od -An -v -tx1 "$PANIC_TRACE" | tr -d ' \n')"
if [ "$PANIC_HEX" != "0d0000007f000000000000000001000000" ]; then
  echo "FAIL: expected only END(1) in panic trace, got $PANIC_HEX"
  exit 1
fi
echo "  panic wrote END(1)"

echo "== deterministic rendezvous regression: thread depth isolation"
PROBE_SRC="$WORK/frame_threads.iyi"
cat << 'EOF' > "$PROBE_SRC"
module test/frame_threads
import std/observe
import std/env::{ENV}

class FrameHold
  getter go : Atomic(Int64)
  getter open : Atomic(Int64)
  getter done : Atomic(Int64)
  def initialize
    @go = Atomic(Int64).new(0_i64)
    @open = Atomic(Int64).new(0_i64)
    @done = Atomic(Int64).new(0_i64)
  end
end

hold = FrameHold.new
holder = IyiThread.start do
  while hold.go.get == 0_i64
  end
  Std::Observe.enter_frame
  hold.open.set(1_i64)
  while hold.done.get == 0_i64
  end
  Std::Observe.leave_frame
  nil
end
hold.go.set(1_i64)
while hold.open.get == 0_i64
end
ENV["IYI_FRAME_PROBE"]?
hold.done.set(1_i64)
holder.join
EOF

PROBE_TRACE="$WORK/probe_trace.bin"
rm -f "$PROBE_TRACE"
IYI_OBSERVE="$PROBE_TRACE" "$IYI" run -Diyi_observe "$PROBE_SRC"

if [ ! -f "$PROBE_TRACE" ]; then
  echo "FAIL: probe trace was not created"
  exit 1
fi

PROBE_HEX="$(od -An -v -tx1 "$PROBE_TRACE" | tr -d ' \n')"
# 4959495f4652414d455f50524f4245 is "IYI_FRAME_PROBE"
case "$PROBE_HEX" in
  *4959495f4652414d455f50524f4245*) ;;
  *)
    echo "FAIL: expected IYI_FRAME_PROBE in probe trace, got $PROBE_HEX"
    exit 1
    ;;
esac

PROBE_TAIL="$(tail -c 17 "$PROBE_TRACE" | od -An -v -tx1 | tr -d ' \n')"
if [ "$PROBE_TAIL" != "0d0000007f000000000000000000000000" ]; then
  echo "FAIL: expected END(0) at end of probe trace, got $PROBE_TAIL"
  exit 1
fi
echo "  thread depth isolation observed: IYI_FRAME_PROBE recorded while helper held open frame"

echo "== deterministic rendezvous regression: mutation proof (probe can fail)"
PATCH_DIR="$WORK/patched"
mkdir -p "$PATCH_DIR"
cp -R "$REPO/src" "$PATCH_DIR/src"
OBSERVE_PATH="$PATCH_DIR/src/std/observe.iyi"

# Delete the @[ThreadLocal] line directly above @@thread_depth
MUTATED=0
awk '
  /^[[:space:]]*@\[ThreadLocal\][[:space:]]*$/ {
    getline next_line
    if (next_line ~ /@@thread_depth/) {
      print next_line
      print "MUTATED" > "/dev/stderr"
      next
    } else {
      print
      print next_line
      next
    }
  }
  { print }
' "$OBSERVE_PATH" > "$OBSERVE_PATH.tmp" 2>"$WORK/awk_err"
mv "$OBSERVE_PATH.tmp" "$OBSERVE_PATH"

if ! grep -q "MUTATED" "$WORK/awk_err"; then
  echo "FAIL: could not apply mutation: @[ThreadLocal] line above @@thread_depth not found"
  exit 1
fi

MUT_TRACE="$WORK/mut_trace.bin"
rm -f "$MUT_TRACE"
IYI_PATH="$PATCH_DIR/src${PSEP}$REPO/samples/iyi" IYI_OBSERVE="$MUT_TRACE" "$IYI" run -Diyi_observe "$PROBE_SRC"

MUT_HEX="$(od -An -v -tx1 "$MUT_TRACE" | tr -d ' \n')"
case "$MUT_HEX" in
  *4959495f4652414d455f50524f4245*)
    echo "FAIL: probe does not discriminate: IYI_FRAME_PROBE appeared even without @[ThreadLocal]"
    exit 1
    ;;
  *)
    echo "  mutation proof passed: without @[ThreadLocal], helper frame suppressed main thread observation"
    ;;
esac

echo "OK: bench/std_observe_exercise.sh passed all checks"
