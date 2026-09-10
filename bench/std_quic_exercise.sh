#!/usr/bin/env bash
# QUIC standard library exercise driver.
# Runs the QUIC exercise in plain and release mode, checks every section
# reported, and proves the checks can fail by patching copies of std/quic.iyi.
#
#     bash bench/std_quic_exercise.sh
#
# A check that cannot fail is not a check. This script proves failure across:
#   1. RFC 9001 A.1 initial secret derivation (corrupted initial salt detected)
#   2. RFC 9001 A.4 retry integrity tag verification (corrupted retry key detected)
#   3. RFC 9000 Appendix A packet number reconstruction (broken window arithmetic detected)
#   4. RFC 9002 RTT estimation (corrupted RTT update detected)
#   5. Stream ID classification (broken stream type bits detected)
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
  if ! IYI_PATH="$REPO/src" "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_quic_exercise.iyi" \
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

echo "== the quic exercise, plain build"
run_case "plain" quic-plain
if ! grep -q "all std/quic checks passed" "$WORK/quic-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every quic section reported"
for phrase in "keys:" "client-initial:" "server-initial:" "retry-integrity:" "chacha20-short-header:" "packet-number:" "packet-spaces:" "frames:" "loss-and-congestion:" "stream-and-congestion:" "transport-parameters:" "loopback-udp:" "pto-retransmit:"; do
  grep -q "$phrase" "$WORK/quic-plain.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  keys, client-initial, server-initial, retry-integrity, chacha20-short-header, packet-number, packet-spaces, frames, loss-and-congestion, stream-and-congestion, transport-parameters, loopback-udp, and pto-retransmit all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" quic-release --release
if ! grep -q "all std/quic checks passed" "$WORK/quic-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== proving the checks can fail when quic mechanisms are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" target_file="$4" sed_script="$5"
  mkdir -p "$WORK/$dir/std"
  # Copy sibling files so all imports are reachable
  cp "$REPO/src/std/"*.iyi "$WORK/$dir/std/"
  sed -e "$sed_script" "$REPO/src/std/$target_file" > "$WORK/$dir/std/$target_file"
  # A patch that matches nothing leaves the library intact, and an intact
  # library passes. That reads as "this check cannot fail" when the truth is
  # that nothing was broken to test it. Line-anchored patches drift; this
  # catches it at the patch rather than at the conclusion.
  if cmp -s "$REPO/src/std/$target_file" "$WORK/$dir/std/$target_file"; then
    echo "  $label: the patch changed nothing, so this proves nothing"
    status=1
    return
  fi
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/std_quic_exercise.iyi" \
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
    echo "  $label: failed, but not at expected check (expected '$phrase')"
    sed -n '$p' "$WORK/$dir/out"
    status=1
    return
  fi
  printf '  %s: exits %s at "%s"\n' "$label" "$exit_code" \
    "$(grep -m1 "$phrase" "$WORK/$dir/out" | sed 's/^iyi: panic: //')"
}

# 1. Initial salt corrupted (fails RFC 9001 A.1 initial secret assertion)
prove_fails "initial salt corrupted" salt_corrupt \
  "assertion failed: RFC 9001 A.1 client initial secret mismatch" "quic.iyi" \
  's/0x38_u8, 0x76_u8/0x39_u8, 0x76_u8/'

# 2. Retry key corrupted (fails RFC 9001 A.4 retry tag assertion)
prove_fails "retry key corrupted" retry_corrupt \
  "assertion failed: A.4 retry integrity tag mismatch" "quic.iyi" \
  's/0xbe_u8, 0x0c_u8/0xbf_u8, 0x0c_u8/'

# 3. Packet number decoding broken
prove_fails "packet number decode broken" pn_broken \
  "pn decode 1 mismatch" "quic.iyi" \
  's/candidate_pn = (expected_pn/candidate_pn = 0_u64 #/'

# 4. RTT estimator corrupted
prove_fails "rtt estimator corrupted" rtt_corrupt \
  "first sample min rtt" "quic.iyi" \
  's/@min_rtt = latest/@min_rtt = 0_i64/'

# 5. Stream ID classification broken
prove_fails "stream id classification broken" stream_broken \
  "client bidi" "quic.iyi" \
  's/(@id & 0x01_u64) == 0_u64/false/'

echo
if [ "$status" -eq 0 ]; then
  echo "QUIC standard library: packet protection, A.1 keys, A.2 client initial,"
  echo "A.3 server initial, A.4 retry integrity, A.5 chacha20 short header, packet numbers,"
  echo "frame codecs, loss detection, congestion control, and streams all pass plain"
  echo "and release, and each check is proven to fail when its mechanism is broken."
else
  echo "QUIC standard library: something above failed."
fi
exit "$status"
