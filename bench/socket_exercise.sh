#!/usr/bin/env bash
# Sockets, driven. Runs the socket exercise plain and optimised,
# checks each phase reached its expected output, tests connection refusal,
# and proves each check can fail via patched copies of the prelude.
#
#   bash bench/socket_exercise.sh
#
# Needs `make` first. Exits non-zero if any check fails.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

run_case() {
  local label="$1" name="$2"
  shift 2
  if ! "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/socket_exercise.iyi" \
       >"$WORK/$name.build.log" 2>&1; then
    echo "$label: build failed"
    sed -n '1,12p' "$WORK/$name.build.log"
    status=1
    return 1
  fi
  "$WORK/$name" >"$WORK/$name.out" 2>&1
  local exit_code=$?
  sed 's/^/  /' "$WORK/$name.out"
  if [ "$exit_code" -ne 0 ]; then
    echo "$label: exited $exit_code"
    status=1
    return 1
  fi
  return 0
}

echo "== the socket exercise, plain build"
run_case "plain" socket-exercise
if ! grep -q "all checks passed" "$WORK/socket-exercise.out" 2>/dev/null; then
  echo "  MISSING: the run did not reach the end"
  status=1
fi

echo
echo "== every socket check reported"
for phrase in connect_accept message_exchange short_read closed_peer; do
  grep -q "$phrase: ok" "$WORK/socket-exercise.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  connect_accept, message_exchange, short_read and closed_peer all reported ok"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" socket-exercise-release --release
if ! grep -q "all checks passed" "$WORK/socket-exercise-release.out" 2>/dev/null; then
  echo "  MISSING: the optimised build did not reach the end"
  status=1
fi

echo
echo "== refused connection exits non-zero with diagnostic"
"$WORK/socket-exercise" refused >"$WORK/refused.out" 2>&1
exit_code=$?
if [ "$exit_code" -eq 0 ]; then
  echo "  refused connection unexpectedly succeeded"
  status=1
elif ! grep -q "cannot connect to 127.0.0.1:" "$WORK/refused.out"; then
  echo "  refused connection failed with unexpected message:"
  sed 's/^/    /' "$WORK/refused.out"
  status=1
else
  printf '  refused connection: exits %s at "%s"\n' "$exit_code" \
    "$(grep -m1 "cannot connect to 127.0.0.1:" "$WORK/refused.out" | sed 's/^iyi: panic: //')"
fi

echo
echo "== the checks fail when the socket mechanism is broken"
prove_fails() {
  local label="$1" dir="$2" phrase="$3" script="$4"
  mkdir -p "$WORK/$dir/iyi"
  cp -R "$REPO/src/iyi/." "$WORK/$dir/iyi/"
  awk "$script" "$REPO/src/iyi/socket.iyi" > "$WORK/$dir/iyi/socket.iyi"
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/socket_exercise.iyi" \
       >"$WORK/$dir/build.log" 2>&1; then
    echo "  $label: the patched prelude did not build"
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
    echo "  $label: failed, but not at the expected check"
    sed -n '$p' "$WORK/$dir/out"
    status=1
    return
  fi
  printf '  %s: exits %s at "%s"\n' "$label" "$exit_code" \
    "$(grep -m1 "$phrase" "$WORK/$dir/out" | sed 's/^iyi: panic: //')"
}

# 1. Broken payload reception
prove_fails "message payload mismatch" badpayload "message_exchange:" \
  '{ sub(/target\.copy_from\(buffer, count\.to_i32\)/, "target[0] = 63_u8"); print }'

# 2. Broken short read (clamping buffer size below 16 bytes alters chunk size)
prove_fails "short read size mismatch" badshort "short_read:" \
  '{ sub(/buffer = Pointer\(UInt8\)\.malloc\(max_bytes\.to_u64\)/, "if max_bytes < 16; max_bytes = 1; end; buffer = Pointer(UInt8).malloc(max_bytes.to_u64)"); print }'
# 3. Broken closed peer detection (does not answer empty string on EOF)
prove_fails "closed peer EOF missed" badoff "closed_peer:" \
  '{ sub(/return "" if count == 0_i64/, "return \"eof_missed\" if count == 0_i64"); print }'

# 4. Broken local port (answers 0 instead of assigned ephemeral port)
prove_fails "local port returns 0" badport "local_port failed:" \
  '{ sub(/\(high << 8\) \| low/, "0"); print }'

echo
if [ "$status" -eq 0 ]; then
  echo "Sockets: connect, accept, message exchange, short reads, closed peer, and"
  echo "refused connections all verified, and checks proved to fail when broken."
else
  echo "Sockets: something above failed."
fi
exit "$status"
