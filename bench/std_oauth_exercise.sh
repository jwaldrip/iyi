#!/usr/bin/env bash
# RFC 5849 (OAuth 1.0) exercise driver for std/oauth. Runs the exercise in
# plain and release mode, checks every section it reports, and proves the
# checks can fail by patching copies of std/oauth.iyi.
#
#     bash bench/std_oauth_exercise.sh
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
  if ! IYI_PATH="$REPO/src" "$IYI" build "$@" -o "$WORK/$name" "$REPO/bench/std_oauth_exercise.iyi" \
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

echo "== std/oauth exercise (RFC 5849), plain build"
run_case "plain" oauth1-plain
if ! grep -q "ALL CHECKS PASSED" "$WORK/oauth1-plain.out" 2>/dev/null; then
  echo "  MISSING: plain build did not reach the end"
  status=1
fi

echo
echo "== every section reported"
for phrase in "Section 1.2: temporary credentials" "Section 1.2: token request" "Section 1.2: protected resource" "Section 3.4.1.1: base string" "Section 3.6: percent-encoding"; do
  grep -q "$phrase" "$WORK/oauth1-plain.out" 2>/dev/null || {
    echo "  MISSING: nothing reported for $phrase"
    status=1
  }
done
[ "$status" -eq 0 ] && echo "  Section 1.2 (three requests), Section 3.4.1.1, and Section 3.6 all reported"

echo
echo "== the same program with optimisation on (--release)"
run_case "release" oauth1-release --release
if ! grep -q "ALL CHECKS PASSED" "$WORK/oauth1-release.out" 2>/dev/null; then
  echo "  MISSING: release build did not reach the end"
  status=1
fi

echo
echo "== proving the checks can fail when OAuth 1.0 protections are broken"

prove_fails() {
  local label="$1" dir="$2" phrase="$3" sed_script="$4"
  mkdir -p "$WORK/$dir/std"
  # Copy sibling files so all standard modules are reachable
  cp "$REPO/src/std/"*.iyi "$WORK/$dir/std/"
  sed -e "$sed_script" "$REPO/src/std/oauth.iyi" > "$WORK/$dir/std/oauth.iyi"
  if cmp -s "$REPO/src/std/oauth.iyi" "$WORK/$dir/std/oauth.iyi"; then
    echo "  $label: the patch changed nothing, so this proves nothing"
    status=1
    return
  fi
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build \
       -o "$WORK/$dir/program" "$REPO/bench/std_oauth_exercise.iyi" \
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

# 1. Parameters sorted in the wrong direction (RFC 5849 Section 3.4.1.3.2).
prove_fails "parameters sorted descending" sort_descending \
  "RFC 5849 Section 1.2 initiate signature" \
  's/swap = if a\[0\] > b\[0\]/swap = if a[0] < b[0]/'

# 2. A space encoded as `+` where Section 3.6 requires %20.
prove_fails "space encoded as +" space_as_plus \
  "RFC 5849 Section 3.4.1.1 base string" \
  's/space_to_plus: false/space_to_plus: true/g'

# 3. The `&` between the consumer and token secrets replaced by `+`.
prove_fails "secret separator is +" separator_plus \
  "RFC 5849 Section 1.2 initiate signature" \
  's/enc_client + "&" + enc_token/enc_client + "+" + enc_token/'

# 4. The oauth_nonce dropped from the Authorization header (the signature
#    itself is unaffected, so only the header check can catch it).
prove_fails "nonce dropped from header" nonce_dropped \
  "RFC 5849 Section 1.2 Authorization header" \
  's/auth.add("oauth_nonce", nonce)/auth.add("oauth_nonce", "")/'

echo
if [ "$status" -eq 0 ]; then
  echo "== all std/oauth checks passed"
else
  echo "== std/oauth checks FAILED"
fi

exit "$status"
