#!/usr/bin/env bash
# Security parity standard library exercise driver.
# Runs the security parity exercise in plain and release mode, checks every
# section reported, and proves the checks can fail by patching copies of
# std/digest.iyi, std/crypto.iyi, std/openssl.iyi and std/compress.iyi.
#
#     bash bench/std_security_parity_exercise.sh
#
# A check that cannot fail is not a check. This script proves failure across:
#   1. Adler-32 combine integrity (combined checksum corrupted)
#   2. Bcrypt verification (forged acceptance of a wrong password)
#   3. Subtle constant-time comparison (forged equality refused)
#   4. AES-128-GCM tampered tag rejection (authentication bypass refusal)
#   5. PBKDF2 key derivation (corrupted PRK detected)
#   6. AES-128-CBC round trip (zeroed key detected)
#   7. Zip entry compression method (misread method detected)
#   8. Bounded decompression (removed literal limit detected)
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
  if ! "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_security_parity_exercise.iyi" \
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

echo "== the security parity exercise, plain build"
run_case "plain" security-plain
if ! grep -q "all std security parity checks passed" "$WORK/security-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every security section reported"
for phrase in "digest:" "crypto:" "openssl:" "aead rejection:" "compress:" "bounded decompress:"; do
  if ! grep -q "  $phrase" "$WORK/security-plain.out" 2>/dev/null; then
    echo "  MISSING: nothing reported for ${phrase%:}:"
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "  digest, crypto, openssl, aead rejection, compress, and bounded decompress all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" security-release --release
if ! grep -q "all std security parity checks passed" "$WORK/security-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== proving the checks can fail when security protections are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" target_file="$4" sed_script="$5"
  mkdir -p "$WORK/$dir/std"
  cp "$REPO/src/std/$target_file" "$WORK/$dir/std/"
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
       -o "$WORK/$dir/program" "$REPO/bench/std_security_parity_exercise.iyi" \
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

# 1. Adler-32 combine corrupted (drops the second summand)
prove_fails "adler32 combine corrupted" adler_combine \
  "assertion failed: Adler32 combine matches" "digest.iyi" \
  's/s1 = (s1_1 [+] s1_2 [+] 65521_u64 - 1_u64) % 65521_u64/s1 = s1_1 % 65521_u64/'

# 6. Cipher key zeroed (AES-128-CBC vector no longer matches)
prove_fails "aes-128-cbc key zeroed" cbc_key \
  "assertion failed: AES-128-CBC NIST Case F.2.1" "openssl.iyi" \
  's/@key = k\[0, key_len\]/@key = Bytes.new(key_len)/'

# 2. Bcrypt verify always accepts (forged password acceptance)
prove_fails "bcrypt wrong password accepted" bcrypt_accept \
  "assertion failed: Bcrypt verify incorrect" "crypto.iyi" \
  's/@digest == hashed_digest/true/'

# 3. Subtle constant-time compare forged (always equal)
prove_fails "subtle compare forged" subtle_forged \
  "assertion failed: Subtle constant_time_compare ne" "crypto.iyi" \
  's/Std::Crypto.constant_time_compare(a, b)/true/g'

# 4. AES-128-GCM tag verification bypassed (must fail: tampered tag accepted)
prove_fails "aes-128-gcm tampered tag accepted" aead_gcm \
  "assertion failed: AES-128-GCM tampered tag rejected" "crypto.iyi" \
  '/def self.gcm_decrypt_detached/,/^  end$/s/return nil unless Std::Crypto.constant_time_compare(tag, expected_tag)/# bypass/'

# 5. PBKDF2 PRK corrupted (derives from the wrong block)
prove_fails "pbkdf2 prk corrupted" pbkdf2_corrupt \
  "assertion failed: PKCS5 SHA1 c=1" "openssl.iyi" \
  's/u = Std::Crypto::HMAC.digest(algo_sym, sec_bytes, salt_block)/u = Std::Crypto::HMAC.digest(algo_sym, sec_bytes, sec_bytes)/'


# 7. Zip compression method misread (deflated entries read as stored)
prove_fails "zip method misread" zip_method \
  "assertion failed: Zip entry deflated" "compress.iyi" \
  's/method = method_val.to_i32 == 8 ? CompressionMethod::DEFLATED : CompressionMethod::STORED/method = CompressionMethod::STORED/'

# 8. Bounded decompression literal limit removed (zip bomb inflates fully)
prove_fails "bounded decompress limit bypassed" bomb_limit \
  "assertion failed: Decompression bound limit enforced" "compress.iyi" \
  's/if @max_output_size >= 0_i64 && @out_buf.size.to_i64 >= @max_output_size # GUARD_MATCH_LIMIT/if false/'

echo
if [ "$status" -eq 0 ]; then
  echo "Security parity standard library: digest vectors and combine, crypto"
  echo "primitives, OpenSSL compatibility, AEAD rejection, compress APIs, and"
  echo "bounded decompression all pass plain and optimised, and each check is"
  echo "proven to fail when its mechanism is broken."
else
  echo "SOME CHECKS FAILED (status $status)"
fi
exit "$status"
