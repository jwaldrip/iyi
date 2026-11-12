#!/usr/bin/env bash
# RFC 6749 (OAuth 2.0), RFC 6750 (Bearer) and draft-ietf-oauth-v2-http-mac
# exercise driver for std/oauth2. Runs the exercise in plain and release mode,
# checks every section it reports, proves the refusals it relies on happen in
# a separate process, and proves the checks can fail by patching copies of the
# standard library.
#
#     bash bench/std_oauth2_exercise.sh
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
  if ! IYI_PATH="$REPO/src" "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_oauth2_exercise.iyi" \
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

echo "== std/oauth2 exercise, plain build"
run_case "plain" oauth2-plain
if ! grep -q "std/oauth2 request and token checks all passed" "$WORK/oauth2-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every section reported"
for phrase in "authorization code request" "client credentials with the RequestBody scheme" "refresh request" "access token parsing" "Authorization header values" "session expiry"; do
  grep -q "$phrase" "$WORK/oauth2-plain.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  authorization code request, client credentials, refresh request, access token parsing, Authorization header values, and session expiry all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" oauth2-release --release
if ! grep -q "std/oauth2 request and token checks all passed" "$WORK/oauth2-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== refusals, each in its own process (the module raises; nothing here catches it)"

# A program that calls one thing and must refuse. Passing means: non-zero
# exit and the expected message.
refuse_case() {
  local label="$1" name="$2" phrase="$3" body="$4"
  mkdir -p "$WORK/$name"
  cat > "$WORK/$name/main.iyi" <<IYI
module $name

import std/oauth2::{AccessToken, Client, AuthScheme}
import std/http::{Request, Response, Headers}
import std/uri::{Params}

class StatusTransport < Std::Oauth::Client
  property response_status : Int32
  property response_body : String

  def initialize(@response_status : Int32, @response_body : String)
    super("127.0.0.1", 80)
  end

  def post(path : String, headers : Headers? = nil, body : String = "", form : String | Params | Nil = nil) : Response
    Response.new(@response_status, @response_body, headers || Headers.new)
  end
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
    echo "  $label: returned a token, so the refusal is not checked"
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

refuse_case "string expires_in" refuse_string_expires "expected int, got String" \
  'puts AccessToken.from_json("{\"access_token\": \"x\", \"token_type\": \"bearer\", \"expires_in\": \"3600\"}").to_json'
refuse_case "truncated JSON body" refuse_truncated "unexpected end of input" \
  'puts AccessToken.from_json("{\"access_token\": ").to_json'
refuse_case "no access_token" refuse_no_access "Missing access token in JSON response" \
  'puts AccessToken.from_json("{\"token_type\": \"bearer\"}").to_json'
refuse_case "mac token without key" refuse_mac_no_key "Missing mac_algorithm or mac_key" \
  'puts AccessToken.from_json("{\"access_token\": \"m\", \"token_type\": \"mac\"}").to_json'
refuse_case "token endpoint 400" refuse_status "OAuth2 Error: invalid_grant - refresh token expired" \
  'c = Client.new("auth.example.com", "id", "sec")
c.http_client = StatusTransport.new(400, "{\"error\": \"invalid_grant\", \"error_description\": \"refresh token expired\"}")
puts c.get_access_token_using_refresh_token("rt").access_token'

echo
echo "== proving the checks can fail when OAuth 2.0 protections are broken"

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
       -o "$WORK/$dir/program" "$REPO/bench/std_oauth2_exercise.iyi" \
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

# 1. Reserved byte left unencoded in form encoding (`&` passes through std/uri's
#    encode_www_form), so a scope or redirect value splits into two parameters.
prove_fails "form encoding passes '&' raw" uri_amp_raw \
  "authorize URI bytes" "uri.iyi" \
  's/false  *# encode_path_segment, encode_www_form/b == 38_u8 # encode_path_segment, encode_www_form/'

# 2. A token response without token_type is refused instead of read as Bearer.
prove_fails "missing token_type refused" token_type_refused \
  "Unknown token_type in access token json" "oauth2.iyi" \
  's/token_type.downcase : "bearer"/token_type.downcase : "missing"/'

# 3. Expiry computed in milliseconds rather than seconds.
prove_fails "expiry in milliseconds" expiry_ms \
  "refreshed token expires 3600 s from now" "oauth2.iyi" \
  's/Span\.new(seconds: exp_in, nanoseconds: 0)/Span.new(seconds: exp_in * 1000, nanoseconds: 0)/'

# 4. Bearer header written with the wrong scheme name.
prove_fails "Bearer scheme corrupted" bearer_scheme_corrupt \
  "Bearer Authorization header" "oauth2.iyi" \
  's/"Bearer " + @access_token/"Token " + @access_token/'

echo
if [ "$status" -eq 0 ]; then
  echo "== all std/oauth2 checks passed"
else
  echo "== std/oauth2 checks FAILED"
fi

exit "$status"
