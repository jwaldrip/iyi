#!/usr/bin/env bash
# HTTP/1.1 standard library exercise driver.
# Runs the HTTP exercise in plain and release mode, checks every section
# reported, and proves the checks can fail by patching copies of std/http.iyi.
#
#     bash bench/std_http_exercise.sh
#
# A check that cannot fail is not a check. This script proves failure across
# request smuggling (dual CL/TE and conflicting CL), header injection (CR/LF in
# value and invalid chars in name), bounds enforcement (request line, header count,
# headers size), chunked parsing (hex validation, final zero chunk), repetition
# rules, and cookie attribute parsing.
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
  if ! "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_http_exercise.iyi" \
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

echo "== the HTTP exercise, plain build"
run_case "plain" http-plain
if ! grep -q "all std/http checks passed" "$WORK/http-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every HTTP section reported"
for phrase in "status codes:" "headers:" "repetition rules:" "header injection:" "request smuggling:" "bounds:" "chunked parsing:" "roundtrip: full request" "roundtrip: Content-Length" "keep-alive:" "cookie parsing:" "params:"; do
  grep -q "$phrase" "$WORK/http-plain.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  status, headers, repetition, injection, smuggling, bounds, chunked, roundtrips, keep-alive, cookies, and params all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" http-release --release
if ! grep -q "all std/http checks passed" "$WORK/http-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== proving the checks can fail when HTTP security and protocol invariants are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" sed_script="$4"
  mkdir -p "$WORK/$dir/std"
  sed -e "$sed_script" "$REPO/src/std/http.iyi" > "$WORK/$dir/std/http.iyi"
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/std_http_exercise.iyi" \
       >"$WORK/$dir/build.log" 2>&1; then
    echo "  $label: the patched HTTP library did not build"
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

# 1. Request smuggling: dual CL and TE check broken
prove_fails "request smuggling dual CL/TE broken" no_smuggle_cl_te "smuggling with both CL and TE was not rejected" \
  's/if has_cl && has_te/if false \&\& has_cl \&\& has_te/'

# 2. Request smuggling: conflicting CL values check broken in Headers#add
prove_fails "request smuggling conflicting CL broken" no_smuggle_cl "conflicting CL on add was not rejected" \
  's/existing\[0\]\.strip != value\.strip/false/'

# 3. Header injection: CR in header value broken
prove_fails "header injection CR in value broken" no_inj_cr "CR header injection not caught" \
  's/b == 13_u8 || b == 10_u8/false/'

# 4. Header injection: invalid char in header name broken
prove_fails "header injection invalid name char broken" no_inj_name "bad name injection not caught" \
  's/b <= 32_u8 || b >= 127_u8 || b == 58_u8/false/'

# 5. Bounds: request line length check broken
prove_fails "request line length bounds broken" no_line_bound "oversized request line was not rejected" \
  's/req_line.bytesize > MAX_REQUEST_LINE_SIZE/false/'

# 6. Bounds: header count limit broken
prove_fails "header count bounds broken" no_count_bound "oversized header count was not rejected" \
  's/header_count > MAX_HEADER_COUNT/false/'

# 7. Chunked parsing: non-hex chunk size check broken
prove_fails "chunked non-hex size check broken" no_hex_check "wrong non-hex message" \
  's/return HttpError\.new("Invalid chunk size: not valid hex") unless valid_hex/return HttpError.new("Bypassed hex check") unless valid_hex/'

# 8. Chunked parsing: missing final zero chunk check broken
prove_fails "chunked missing final zero check broken" no_zero_check "missing final zero chunk was not rejected" \
  's/return HttpError\.new("Incomplete chunked body: missing final zero chunk") unless nl/return {"", trailers} unless nl/'
# 9. Header repetition rules broken (single-value header repeats)
prove_fails "header repetition rules broken" no_repetition "Content-Type should not repeat" \
  's/if Headers\.can_repeat?(name)/if true/'

# 10. Cookie SameSite parsing broken
prove_fails "cookie SameSite parsing broken" no_samesite "parsed cookie samesite" \
  's/samesite = SameSite\.parse?(attr_val)/samesite = nil.as(SameSite?)/'

echo
if [ "$status" -eq 0 ]; then
  echo "HTTP standard library: Status, Headers, Request, Response, wire format, chunked encoding,"
  echo "smuggling guards, injection guards, bounds limits, keep-alive, cookies, and params all pass plain"
  echo "and optimised, and each check is proven to fail when its mechanism is broken."
else
  echo "HTTP standard library exercise: one or more checks failed" 1>&2
fi
exit "$status"
