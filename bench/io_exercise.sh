#!/usr/bin/env bash
# Exercises IyiIO: short reads, buffer boundaries, EOF, and flushed writes.
#
#     bash bench/io_exercise.sh
#
# Follows the house style: exercises the stream abstraction plain and with
# --release, and proves each check can fail by breaking the mechanism in a
# patched copy of the library.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

run_case() {
  local label="$1" name="$2"
  shift 2
  echo "== $label"
  if ! "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/io_exercise.iyi" >"$WORK/$name.build.log" 2>&1; then
    echo "  $label: build failed"
    sed -n '1,12p' "$WORK/$name.build.log"
    status=1
    return
  fi
  "$WORK/$name" >"$WORK/$name.out" 2>&1
  local exit_code=$?
  if [ "$exit_code" -ne 0 ]; then
    echo "  $label: failed with exit code $exit_code"
    sed -n '$p' "$WORK/$name.out"
    status=1
    return
  fi
  if ! grep -q "all io checks passed" "$WORK/$name.out"; then
    echo "  $label: did not reach all io checks passed"
    status=1
    return
  fi
  echo "  $label: all io checks passed"
}

run_case "the exercise, plain build" io-plain
echo
run_case "the same program with optimisation on" io-release --release

echo
echo "== the checks fail when the mechanism is broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" script="$4"
  mkdir -p "$WORK/$dir/iyi"
  cp -R "$REPO/src/iyi/." "$WORK/$dir/iyi/"
  awk "$script" "$REPO/src/iyi/io.iyi" > "$WORK/$dir/iyi/io.iyi"
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/io_exercise.iyi" \
       >"$WORK/$dir/build.log" 2>&1; then
    echo "  $label: the patched library did not build"
    sed -n '1,12p' "$WORK/$dir/build.log"
    status=1
    return
  fi
  "$WORK/$dir/program" >"$WORK/$dir/out" 2>&1
  local exit_code=$?
  if [ "$exit_code" -eq 0 ]; then
    echo "  $label: the exercise still passed, so it does not test this"
    status=1
    return
  fi
  if ! grep -q "$phrase" "$WORK/$dir/out"; then
    echo "  $label: failed, but not at the expected check ($phrase)"
    sed -n '$p' "$WORK/$dir/out"
    status=1
    return
  fi
  printf '  %s: exits %s at "%s"\n' "$label" "$exit_code" \
    "$(grep -m1 "$phrase" "$WORK/$dir/out" | sed 's/^iyi: panic: //')"
}

# 1. Short reads broken: to_copy becomes 0, so short reads return empty
prove_fails "short reads fail" noshort "short_reads:" \
  '{ sub(/to_copy = avail < needed \? avail : needed/, "to_copy = 0"); print }'

# 2. Buffer boundary broken: multi-buffer fill in read_line returns 0
prove_fails "read across buffer boundary fails" noboundary "buffer_boundary:" \
  '{ sub(/got = fill_buffer/, "got = 0"); print }'

# 3. EOF check broken: eof? always returns false
prove_fails "eof check fails" noeof "eof:" \
  '{ sub(/def eof\? : Bool/, "def eof? : Bool\n    return false"); print }'

# 4. Flush broken: flush is a no-op
prove_fails "flush check fails" noflush "flush:" \
  '{ sub(/def flush : Nil/, "def flush : Nil\n    return"); print }'

echo
if [ "$status" -eq 0 ]; then
  echo "all io exercise checks and failure proofs passed"
fi
exit $status
