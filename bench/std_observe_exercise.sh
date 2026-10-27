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

PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [ -z "$PY" ]; then
  echo "FAIL: python3 or python interpreter required for trace validation"
  exit 1
fi

echo "== concurrent recorder: 8 raw threads race, deduplication, taints, and post-taint drop"
RACE_SRC="$WORK/recorder_race.iyi"
cat << 'EOF' > "$RACE_SRC"
module test/recorder_race
import std/observe

ready = Atomic(Int32).new(0_i32)
go = Atomic(Int32).new(0_i32)
done1 = Atomic(Int32).new(0_i32)
go2 = Atomic(Int32).new(0_i32)

threads = Array(IyiThread).new(8)
8.times do |t|
  threads << IyiThread.start do
    ready.add(1_i32)
    while go.get == 0_i32
    end

    2000.times do |i|
      path = "/iyi-recorder-race/#{t}/#{i}"
      Std::Observe.file_write(1_u8, path)
      Std::Observe.file(1_u8, path)
      env_name = "IYI_RACE_#{t}_#{i}"
      Std::Observe.env_write(env_name)
      Std::Observe.env_get(env_name, "v")
    end

    done1.add(1_i32)
    while go2.get == 0_i32
    end

    # Barrier then kind33/34 reverseorder odds/evens
    if t % 2 == 0
      Std::Observe.not_reusable(33_u8, "entropy_site_#{t}")
      Std::Observe.not_reusable(34_u8, "timer_site_#{t}")
    else
      Std::Observe.not_reusable(34_u8, "timer_site_#{t}")
      Std::Observe.not_reusable(33_u8, "entropy_site_#{t}")
    end

    # After-taint envget + filewrite (must be dropped by recorder)
    Std::Observe.env_get("AFTER_TAINT_#{t}", "v")
    Std::Observe.file_write(1_u8, "/iyi-recorder-race/after/#{t}")
    nil
  end
end

while ready.get < 8_i32
end
go.set(1_i32)

while done1.get < 8_i32
end
go2.set(1_i32)

threads.each do |th|
  th.join
end
EOF

cat << 'EOF' > "$WORK/validate_race_trace.py"
import struct, sys

trace_file = sys.argv[1]
with open(trace_file, "rb") as f:
    data = f.read()

pos = 0
records = []
while pos < len(data):
    if pos + 4 > len(data):
        sys.exit("FAIL: incomplete length header at pos %d of %d" % (pos, len(data)))
    payload_len, = struct.unpack_from("<I", data, pos)
    pos += 4
    if pos + payload_len > len(data):
        sys.exit("FAIL: incomplete payload: need %d bytes, got %d" % (payload_len, len(data) - pos))
    payload = data[pos : pos + payload_len]
    pos += payload_len
    rec_type = payload[0]
    task_id, = struct.unpack_from("<Q", payload, 1)
    body = payload[9:]
    records.append((rec_type, task_id, body))

if not records:
    sys.exit("FAIL: trace contains no records")

if records[-1][0] != 0x7F:
    sys.exit("FAIL: last record is type 0x%02x, expected 0x7f (END)" % records[-1][0])
if len(records[-1][2]) < 4:
    sys.exit("FAIL: END record payload too short")
end_status, = struct.unpack_from("<i", records[-1][2], 0)
if end_status != 0:
    sys.exit("FAIL: END status is %d, expected 0" % end_status)

type_counts = {}
type07_paths = set()
type03_written_first = 0
taint_kinds = []
first_taint_idx = None

for idx, (rec_type, task_id, body) in enumerate(records[:-1]):
    type_counts[rec_type] = type_counts.get(rec_type, 0) + 1
    if rec_type == 0x07: # file_write: op(u8), real(str), target(str), scratch(u8)
        op_code = body[0]
        real_len, = struct.unpack_from("<I", body, 1)
        real = body[5 : 5 + real_len].decode("utf-8", "replace")
        type07_paths.add(real)
    elif rec_type == 0x03: # env_get: name(str), present(u8), val(str), written_first(u8)
        if body and body[-1] == 1:
            type03_written_first += 1
    elif rec_type == 0x08: # taint: kind_code(u8), site(str)
        if first_taint_idx is None:
            first_taint_idx = idx
        kind_code = body[0]
        taint_kinds.append(kind_code)

if type_counts.get(0x07, 0) != 16000:
    sys.exit("FAIL: expected 16000 type07 records, got %d" % type_counts.get(0x07, 0))
if len(type07_paths) != 16000:
    sys.exit("FAIL: expected 16000 unique type07 paths, got %d" % len(type07_paths))
if type_counts.get(0x01, 0) != 0:
    sys.exit("FAIL: expected 0 type01 records (all skipped by written_paths), got %d" % type_counts.get(0x01, 0))
if type_counts.get(0x03, 0) != 16000:
    sys.exit("FAIL: expected 16000 type03 records, got %d" % type_counts.get(0x03, 0))
if type03_written_first != 16000:
    sys.exit("FAIL: expected 16000 type03 with written_first=1, got %d" % type03_written_first)
if type_counts.get(0x04, 0) != 16000:
    sys.exit("FAIL: expected 16000 type04 records, got %d" % type_counts.get(0x04, 0))

if taint_kinds.count(0x21) != 1 or taint_kinds.count(0x22) != 1 or len(taint_kinds) != 2:
    sys.exit("FAIL: expected exactly 1 kind 0x21 and 1 kind 0x22, got %s" % taint_kinds)

for idx, (rec_type, task_id, body) in enumerate(records[:-1]):
    if rec_type != 0x08 and first_taint_idx is not None and idx > first_taint_idx:
        sys.exit("FAIL: non-taint record type 0x%02x at index %d appeared after first taint at index %d" % (rec_type, idx, first_taint_idx))

if b"AFTER_TAINT" in data or b"/iyi-recorder-race/after" in data:
    sys.exit("FAIL: after-taint names appeared in trace")

print("OK: 8-thread race trace valid")
EOF

RACE_TRACE="$WORK/race_trace.bin"
rm -f "$RACE_TRACE"
IYI_OBSERVE="$RACE_TRACE" "$IYI" run -Diyi_observe "$RACE_SRC"
"$PY" "$WORK/validate_race_trace.py" "$RACE_TRACE"
echo "  8-thread race verified: exact counts, written_first=1, 0 self-reads, taints 33/34 deduplicated, post-taints dropped, END last"

echo "== concurrent recorder: mutation proof (nolock discriminates <= 5 attempts)"
MUT_NOLOCK_DIR="$WORK/mut_nolock"
mkdir -p "$MUT_NOLOCK_DIR"
cp -R "$REPO/src" "$MUT_NOLOCK_DIR/src"
MUT_OBSERVE="$MUT_NOLOCK_DIR/src/std/observe.iyi"

"$PY" -c "
with open('$MUT_OBSERVE', 'r') as f:
    content = f.read()

start_tag = '# RECORD_LOCK_START'
end_tag = '# RECORD_LOCK_END'
s_idx = content.find(start_tag)
e_idx = content.find(end_tag)
if s_idx < 0 or e_idx < 0:
    raise Exception('lock tags not found in ' + '$MUT_OBSERVE')
content = content[:s_idx] + '# MUTATED NO-OP LOCK\n' + content[e_idx + len(end_tag):]

start_tag = '# RECORD_UNLOCK_START'
end_tag = '# RECORD_UNLOCK_END'
s_idx = content.find(start_tag)
e_idx = content.find(end_tag)
if s_idx < 0 or e_idx < 0:
    raise Exception('unlock tags not found in ' + '$MUT_OBSERVE')
content = content[:s_idx] + '# MUTATED NO-OP UNLOCK\n' + content[e_idx + len(end_tag):]

with open('$MUT_OBSERVE', 'w') as f:
    f.write(content)
"

MUTATION_FAILED=0
for attempt in 1 2 3 4 5; do
  MUT_RACE_TRACE="$WORK/mut_race_trace_$attempt.bin"
  rm -f "$MUT_RACE_TRACE"
  if ! IYI_PATH="$MUT_NOLOCK_DIR/src${PSEP}$REPO/samples/iyi" IYI_OBSERVE="$MUT_RACE_TRACE" "$IYI" run -Diyi_observe "$RACE_SRC" >/dev/null 2>&1; then
    MUTATION_FAILED=1
    break
  fi
  if ! "$PY" "$WORK/validate_race_trace.py" "$MUT_RACE_TRACE" >/dev/null 2>&1; then
    MUTATION_FAILED=1
    break
  fi
done

if [ "$MUTATION_FAILED" -eq 1 ]; then
  echo "  mutation proof passed: without lock, race caused failure (attempt $attempt)"
else
  echo "FAIL: mutation proof failed: 5 attempts unexpectedly passed without lock"
  exit 1
fi

echo "== concurrent recorder: pool variant (8 g.spawn_parallel tasks)"
POOL_SRC="$WORK/pool_race.iyi"
cat << 'EOF' > "$POOL_SRC"
module test/pool_race
import std/observe
import std/concurrency

group do |g|
  8.times do |t|
    g.spawn_parallel do
      2000.times do |i|
        path = "/iyi-recorder-pool/#{t}/#{i}"
        Std::Observe.file_write(1_u8, path)
        Std::Observe.file(1_u8, path)
        env_name = "IYI_POOL_#{t}_#{i}"
        Std::Observe.env_write(env_name)
        Std::Observe.env_get(env_name, "v")
      end
    end
  end
end
EOF

cat << 'EOF' > "$WORK/validate_pool_trace.py"
import struct, sys

trace_file = sys.argv[1]
with open(trace_file, "rb") as f:
    data = f.read()

pos = 0
records = []
while pos < len(data):
    if pos + 4 > len(data):
        sys.exit("FAIL: incomplete length header")
    payload_len, = struct.unpack_from("<I", data, pos)
    pos += 4
    if pos + payload_len > len(data):
        sys.exit("FAIL: incomplete payload")
    payload = data[pos : pos + payload_len]
    pos += payload_len
    rec_type = payload[0]
    task_id, = struct.unpack_from("<Q", payload, 1)
    body = payload[9:]
    records.append((rec_type, task_id, body))

if not records or records[-1][0] != 0x7F:
    sys.exit("FAIL: expected END(0) last")
end_status, = struct.unpack_from("<i", records[-1][2], 0)
if end_status != 0:
    sys.exit("FAIL: expected END status 0")

type_counts = {}
type07_paths = set()
type03_written_first = 0

for rec_type, task_id, body in records[:-1]:
    type_counts[rec_type] = type_counts.get(rec_type, 0) + 1
    if rec_type == 0x07:
        op_code = body[0]
        real_len, = struct.unpack_from("<I", body, 1)
        real = body[5 : 5 + real_len].decode("utf-8", "replace")
        type07_paths.add(real)
    elif rec_type == 0x03:
        if body and body[-1] == 1:
            type03_written_first += 1

if type_counts.get(0x07, 0) != 16000:
    sys.exit("FAIL: pool expected 16000 type07, got %d" % type_counts.get(0x07, 0))
if len(type07_paths) != 16000:
    sys.exit("FAIL: pool expected 16000 unique type07 paths, got %d" % len(type07_paths))
if type_counts.get(0x01, 0) != 0:
    sys.exit("FAIL: pool expected 0 type01, got %d" % type_counts.get(0x01, 0))
if type_counts.get(0x03, 0) != 16000:
    sys.exit("FAIL: pool expected 16000 type03, got %d" % type_counts.get(0x03, 0))
if type03_written_first != 16000:
    sys.exit("FAIL: pool expected 16000 type03 written_first=1, got %d" % type03_written_first)
if type_counts.get(0x04, 0) != 16000:
    sys.exit("FAIL: pool expected 16000 type04, got %d" % type_counts.get(0x04, 0))

print("OK: pool variant trace valid")
EOF

POOL_TRACE="$WORK/pool_trace.bin"
rm -f "$POOL_TRACE"
IYI_OBSERVE="$POOL_TRACE" "$IYI" run -Diyi_observe "$POOL_SRC"
"$PY" "$WORK/validate_pool_trace.py" "$POOL_TRACE"
echo "  pool variant verified: finished without deadlock/hang, exact counts written"

echo "== concurrent recorder: END race (host late + main returns after 200)"
END_RACE_SRC="$WORK/end_race.iyi"
cat << 'EOF' > "$END_RACE_SRC"
module test/end_race
import std/observe

count = Atomic(Int64).new(0_i64)
stop = Atomic(Int32).new(0_i32)

th = IyiThread.start do
  while stop.get == 0_i32
    Std::Observe.host("late-host")
    count.add(1_i64)
  end
  nil
end

while count.get < 200_i64
end
EOF

cat << 'EOF' > "$WORK/validate_end_race.py"
import struct, sys

trace_file = sys.argv[1]
with open(trace_file, "rb") as f:
    data = f.read()

pos = 0
records = []
while pos < len(data):
    if pos + 4 > len(data):
        sys.exit("FAIL: incomplete length header")
    payload_len, = struct.unpack_from("<I", data, pos)
    pos += 4
    if pos + payload_len > len(data):
        sys.exit("FAIL: incomplete payload")
    payload = data[pos : pos + payload_len]
    pos += payload_len
    rec_type = payload[0]
    task_id, = struct.unpack_from("<Q", payload, 1)
    body = payload[9:]
    records.append((rec_type, task_id, body))

if not records:
    sys.exit("FAIL: empty trace in end race")
if records[-1][0] != 0x7F:
    sys.exit("FAIL: expected END(0) as last record, got 0x%02x" % records[-1][0])
end_status, = struct.unpack_from("<i", records[-1][2], 0)
if end_status != 0:
    sys.exit("FAIL: expected END status 0")

host_count = sum(1 for r in records[:-1] if r[0] == 0x06)
if host_count < 200:
    sys.exit("FAIL: expected at least 200 host records, got %d" % host_count)

print("OK: END race trace valid")
EOF

END_RACE_TRACE="$WORK/end_race_trace.bin"
rm -f "$END_RACE_TRACE"
IYI_OBSERVE="$END_RACE_TRACE" "$IYI" run -Diyi_observe "$END_RACE_SRC"
"$PY" "$WORK/validate_end_race.py" "$END_RACE_TRACE"
echo "  END race verified: END(0) is last record with no trailing records after main returned"

echo "== concurrent recorder: allocation measurement (shared writer < 256 bytes/record)"
ALLOC_SRC="$WORK/alloc_measure.iyi"
cat << 'EOF' > "$ALLOC_SRC"
module test/alloc_measure
import std/observe
import std/gc

names = Array(String).new(10000)
10000.times do |i|
  names << "PREBUILT_ENV_VAR_#{i}"
end

GC.disable
before = IyiHeap.allocated_word.value.get

10000.times do |i|
  Std::Observe.env_get(names[i], "v")
end

after = IyiHeap.allocated_word.value.get
GC.enable

delta = after - before
per_record = delta.to_f / 10000.0
puts "ALLOC_DELTA=#{delta}"
puts "ALLOC_PER_RECORD=#{per_record}"
if per_record >= 256.0
  raise "FAIL: allocation per record too high: #{per_record} bytes/record >= 256"
end
puts "OK: allocation per record < 256 bytes verified"
EOF

ALLOC_TRACE="$WORK/alloc_trace.bin"
rm -f "$ALLOC_TRACE"
IYI_OBSERVE="$ALLOC_TRACE" "$IYI" run -Diyi_observe "$ALLOC_SRC"
echo "  allocation measurement verified: shared resettable RecordWriter allocates < 256 bytes/record"


echo "OK: bench/std_observe_exercise.sh passed all checks"
