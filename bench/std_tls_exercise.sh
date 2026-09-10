#!/usr/bin/env bash
# TLS 1.3 standard library exercise driver.
# Runs the TLS exercise in plain and release mode, checks every section
# reported, and proves the checks can fail by patching copies of std/tls.iyi.
#
#     bash bench/std_tls_exercise.sh
#
# A check that cannot fail is not a check. This script proves failure across:
#   1. X25519 all-zero shared secret detection
#   2. Ed25519 signature forgery refusal
#   3. ECDSA P-256 signature forgery refusal
#   4. RSA-PSS signature forgery refusal
#   5. Record layer tampered tag rejection
#   6. Certificate validity expiration enforcement
#   7. Hostname mismatch refusal
#
# Exits non-zero if any check fails.

set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

run_case() {
  local mode="$1" name="$2"
  shift 2
  # IYI_PATH is named here rather than inherited. Without it this build only
  # resolves the module for someone whose shell already exports the path, so
  # the gate passed for its author and was red for CI and for everyone else.
  if ! IYI_PATH="$REPO/src" "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_tls_exercise.iyi" \
       >"$WORK/$name.build.log" 2>&1; then
    echo "  $mode: build failed"
    sed -n '1,12p' "$WORK/$name.build.log"
    status=1
    return
  fi
  if ! "$WORK/$name" >"$WORK/$name.out" 2>&1; then
    echo "  $mode: run failed"
    sed -n '1,20p' "$WORK/$name.out"
    status=1
    return
  fi
  printf '  %s: passes all checks\n' "$mode"
}

echo "== the tls exercise, plain build"
run_case "plain" tls-plain
if ! grep -q "all std/tls checks passed" "$WORK/tls-plain.out" 2>/dev/null; then
  echo "  expected success line 'all std/tls checks passed' not found"
  status=1
fi

echo
echo "== every tls section reported"
for phrase in "x25519:" "ed25519:" "p256:" "rsa:" "rfc8448:" "x509:" "negative_proofs:" "live_connect:"; do
  if ! grep -q "^$phrase" "$WORK/tls-plain.out" 2>/dev/null; then
    echo "  missing section: $phrase"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "  x25519, ed25519, p256, rsa, rfc8448, x509, negative_proofs, and live_connect all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" tls-release --release
if ! grep -q "all std/tls checks passed" "$WORK/tls-release.out" 2>/dev/null; then
  echo "  expected success line 'all std/tls checks passed' not found in release build"
  status=1
fi

echo
echo "== proving the checks can fail when security protections are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" target_file="$4" sed_script="$5"
  mkdir -p "$WORK/$dir/std"
  # Copy all standard library files so imports resolve cleanly
  cp "$REPO/src/std/"*.iyi "$WORK/$dir/std/"
  sed -e "$sed_script" "$REPO/src/std/$target_file" > "$WORK/$dir/std/$target_file"

  # A patch that matches nothing leaves the library intact, and an intact
  # library passes. That reads as 'this check cannot fail' when the truth is
  # that nothing was broken to test it. Line-anchored patches drift; this
  # catches it at the patch rather than at the conclusion.
  if cmp -s "$REPO/src/std/$target_file" "$WORK/$dir/std/$target_file"; then
    echo "  $label: the patch changed nothing, so this proves nothing"
    status=1
    return
  fi

  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/std_tls_exercise.iyi" \
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

# 1. X25519 all-zero shared secret detection bypassed
prove_fails "x25519 all-zero detection bypassed" x25519_bypass \
  "assertion failed: X25519 all-zero detection" "tls.iyi" \
  's/diff == 0_u8/false/'

# 2. Ed25519 signature forgery accepted
prove_fails "ed25519 signature forgery accepted" ed25519_forge \
  "assertion failed: Ed25519 tampered signature rejected" "tls.iyi" \
  's/diff1.zero? && diff2.zero?/true/'

# 3. ECDSA P-256 signature forgery accepted
prove_fails "p256 signature forgery accepted" p256_forge \
  "assertion failed: ECDSA P-256 tampered signature rejected" "tls.iyi" \
  's/v == r/true/'

# 4. RSA-PSS signature forgery accepted
prove_fails "rsa-pss signature forgery accepted" rsa_forge \
  "assertion failed: RSA-PSS tampered signature rejected" "tls.iyi" \
  's/return false if em\[em_len - 1\] != 0xbc_u8/return true # bypass/'

# 5. Record layer tampered tag accepted
prove_fails "record layer tampered tag accepted" record_tamper \
  "assertion failed: Record layer tampered tag rejected" "tls.iyi" \
  's/return nil if pt.nil?/pt = pt || Bytes.new(16, 0x16_u8)/'

# 6. Certificate validity expiration bypassed
prove_fails "certificate validity expiration bypassed" cert_validity \
  "assertion failed: Certificate not valid before notBefore" "tls.iyi" \
  's/@not_before <= time_sec && time_sec <= @not_after/true/'

# 7. Hostname mismatch accepted
prove_fails "hostname mismatch accepted" hostname_mismatch \
  "assertion failed: Certificate does not match 'other.com'" "tls.iyi" \
  's/return true if pattern == target/return true/'
echo
if [ "$status" -eq 0 ]; then
  echo "all std_tls_exercise checks passed in plain and release modes, with every failure proof active"
else
  echo "std_tls_exercise failed"
fi
exit "$status"
