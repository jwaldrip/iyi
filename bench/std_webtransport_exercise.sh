#!/usr/bin/env bash
# WebTransport (draft-ietf-webtrans-http3) exercise driver for std/webtransport.
# Runs the exercise in plain and release mode, checks every section it reports,
# proves the refusals the module raises happen in a separate process, and
# proves the checks can fail by patching copies of std/webtransport.iyi and
# std/capsule.iyi.
#
#     bash bench/std_webtransport_exercise.sh
#
# Exits non-zero if any check fails.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

run_case() {
  local label="$1" name="$2"
  shift 2
  if ! IYI_PATH="$REPO/src" "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_webtransport_exercise.iyi" \
       >"$WORK/$name.build.log" 2>&1; then
    echo "$label: build failed"
    grep -v 'ld: warning' "$WORK/$name.build.log" | sed -n '1,12p'
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

echo "== std/webtransport exercise, plain build"
run_case "plain" wt-plain
if ! grep -q "ALL CHECKS PASSED" "$WORK/wt-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every section reported"
for phrase in "QUIC variable-length integers" "stream-type headers" "WebTransport datagrams" "CLOSE_WEBTRANSPORT_SESSION" "session state machine"; do
  grep -q "$phrase" "$WORK/wt-plain.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  varints, stream headers, datagrams, close and drain capsules, and the session state machine all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" wt-release --release
if ! grep -q "ALL CHECKS PASSED" "$WORK/wt-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== refusals, each in its own process (the module raises; nothing here catches it)"

refuse_case() {
  local label="$1" name="$2" phrase="$3" body="$4"
  mkdir -p "$WORK/$name"
  cat > "$WORK/$name/main.iyi" <<IYI
module $name

import std/slice::{Bytes}
import std/capsule::{Capsule}
import std/webtransport::{WebTransportSession, BidiStreamHeader, CloseSessionCapsule}

def from_list(xs : Array(UInt8)) : Bytes
  out = Bytes.new(xs.size)
  i = 0
  while i < xs.size
    out[i] = xs[i]
    i = i + 1
  end
  out
end

$body
IYI
  if ! IYI_PATH="$REPO/src" "$IYI" build -o "$WORK/$name/program" "$WORK/$name/main.iyi" \
       >"$WORK/$name/build.log" 2>&1; then
    echo "  $label: did not build"
    grep -v 'ld: warning' "$WORK/$name/build.log" | sed -n '1,8p'
    status=1
    return
  fi
  "$WORK/$name/program" >"$WORK/$name/out" 2>&1
  local exit_code=$?
  if [ "$exit_code" -eq 0 ]; then
    echo "  $label: returned a value, so the refusal is not checked"
    status=1
    return
  fi
  if ! grep -q "$phrase" "$WORK/$name/out"; then
    echo "  $label: refused, but not with '$phrase'"
    sed -n '1,2p' "$WORK/$name/out"
    status=1
    return
  fi
  printf '  %s: exits %s at "%s"\n' "$label" "$exit_code" "$phrase"
}

refuse_case "bidi send before CONNECT response" refuse_send_connecting "cannot send bidi stream in connecting state" \
  's = WebTransportSession.new(4_u64)
puts s.send_bidi_stream(Bytes.new(0)).size'
refuse_case "bidi stream for another session" refuse_session_mismatch "session id mismatch: expected 4, got 8" \
  's = WebTransportSession.new(4_u64)
s.on_connect_response(200)
puts s.receive_bidi_stream(from_list([0x40_u8, 0x41_u8, 0x08_u8])).size'
refuse_case "close value shorter than its code" refuse_close_truncated "close session capsule truncated" \
  'puts CloseSessionCapsule.decode(from_list([0x01_u8, 0x02_u8, 0x03_u8])).reason'
refuse_case "uni type read as bidi" refuse_wrong_stream_type "invalid webtransport bidi stream type" \
  'puts BidiStreamHeader.decode(from_list([0x40_u8, 0x54_u8, 0x04_u8])).size'
refuse_case "capsule length past the buffer" refuse_capsule_overrun "capsule length overruns buffer" \
  'puts Capsule.decode(from_list([0x68_u8, 0x43_u8, 0x07_u8, 0x01_u8, 0x02_u8])).size'

echo
echo "== proving the checks can fail when WebTransport protections are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" target_file="$4" sed_script="$5"
  mkdir -p "$WORK/$dir/std"
  # Copy sibling files so all standard modules are reachable
  cp "$REPO/src/std/"*.iyi "$WORK/$dir/std/"
  sed -e "$sed_script" "$REPO/src/std/$target_file" > "$WORK/$dir/std/$target_file"
  if cmp -s "$REPO/src/std/$target_file" "$WORK/$dir/std/$target_file"; then
    echo "  $label: the patch changed nothing, so this proves nothing"
    status=1
    return
  fi
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/std_webtransport_exercise.iyi" \
       >"$WORK/$dir/build.log" 2>&1; then
    echo "  $label: the patched library did not build"
    grep -v 'ld: warning' "$WORK/$dir/build.log" | sed -n '1,12p'
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
    echo "  $label: failed, but not at expected check (expected '$phrase')"
    sed -n '$p' "$WORK/$dir/out"
    status=1
    return
  fi
  printf '  %s: exits %s at "%s"\n' "$label" "$exit_code" \
    "$(grep -m1 "$phrase" "$WORK/$dir/out" | sed 's/^iyi: panic: //')"
}

# 1. CLOSE_WEBTRANSPORT_SESSION error code off by one in its last byte.
prove_fails "close error code off by one" close_code_off_by_one \
  "close session error code bytes" "webtransport.iyi" \
  's/buf\[3\] = (@error_code & 0xff_u64)/buf[3] = ((@error_code + 1_u64) \& 0xff_u64)/'

# 2. Bidirectional stream type 0x40 instead of 0x41.
prove_fails "bidi stream type 0x40" bidi_type_wrong \
  "bidi stream header bytes" "webtransport.iyi" \
  's/STREAM_TYPE_BIDI = 0x41_u64/STREAM_TYPE_BIDI = 0x40_u64/'

# 3. The QUIC varint 2-byte prefix written as the 4-byte prefix (RFC 9000 A.1).
prove_fails "varint 2-byte prefix wrong" varint_prefix_wrong \
  "canonical varint for 64" "capsule.iyi" \
  's/buf\[0\] = (0x40_u8 | /buf[0] = (0x80_u8 | /'

# 4. Datagram quarter stream id computed as session id // 2, not // 4.
prove_fails "quarter stream id // 2" quarter_id_wrong \
  "datagram bytes for session 8" "webtransport.iyi" \
  's/@session_id \/\/ 4_u64/@session_id \/\/ 2_u64/'

echo
if [ "$status" -eq 0 ]; then
  echo "== all std/webtransport checks passed"
else
  echo "== std/webtransport checks FAILED"
fi

exit "$status"
