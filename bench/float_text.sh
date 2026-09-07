#!/usr/bin/env bash
# `Float64#to_s` (src/iyi/float.iyi): the shortest decimal that reads back
# as the same double, in Crystal's notation. Runs bench/float_text.iyi
# plain and optimised, then proves the check fails by name when the
# printer is broken: the digit loop's stop condition removed (every value
# prints seventeen digits, no longer the shortest), and the notation's
# range widened (ten to the fifteenth prints in fixed form).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

status=0

echo "== the exercise"
for flags in "" "--release"; do
  if ! "$IYI" build $flags -o "$WORK/program" "$REPO/bench/float_text.iyi" > "$WORK/build.log" 2>&1; then
    echo "  build failed ($flags)"; cat "$WORK/build.log" | tail -5; status=1; continue
  fi
  if "$WORK/program" > "$WORK/out" 2>&1 && grep -q "every case printed" "$WORK/out"; then
    echo "  ${flags:-plain}: $(cat "$WORK/out")"
  else
    echo "  ${flags:-plain}: FAILED"; cat "$WORK/out"; status=1
  fi
done

# $1 label, $2 directory, $3 the phrase the failing check prints, $4 awk
# program over float.iyi.
prove_fails() {
  local label="$1" dir="$2" phrase="$3" script="$4"
  mkdir -p "$WORK/$dir/iyi"
  cp -R "$REPO/src/iyi/." "$WORK/$dir/iyi/"
  awk "$script" "$REPO/src/iyi/float.iyi" > "$WORK/$dir/iyi/float.iyi"
  if cmp -s "$WORK/$dir/iyi/float.iyi" "$REPO/src/iyi/float.iyi"; then
    echo "  $label: the awk found nothing to change"; status=1; return
  fi
  if ! IYI_PATH="$WORK/$dir:$REPO/src" "$IYI" build -o "$WORK/$dir/program" "$REPO/bench/float_text.iyi" > "$WORK/$dir/build.log" 2>&1; then
    echo "  $label: the patched prelude did not build"; tail -3 "$WORK/$dir/build.log"; status=1; return
  fi
  set +e
  "$WORK/$dir/program" > "$WORK/$dir/out" 2>&1
  local code=$?
  set -e
  if [ "$code" -eq 0 ]; then
    echo "  $label: the exercise still passed, so it does not test this"; status=1; return
  fi
  if grep -q "$phrase" "$WORK/$dir/out"; then
    echo "  $label: exits $code at \"$(grep -m1 "$phrase" "$WORK/$dir/out")\""
  else
    echo "  $label: failed, but not at the expected check"; cat "$WORK/$dir/out"; status=1
  fi
}

echo
echo "== the check fails when the printer is broken"
prove_fails "digits never stop short" longform "float text:" \
  '{ if ($0 ~ /^      if !low && !high$/) { print "      if count < 17"; next } print }'
prove_fails "notation range widened" widerange "float text: 1.234567890123456e+15" \
  '{ if ($0 ~ /^    if k > -4 && k <= 15$/) { print "    if k > -4 && k <= 16"; next } print }'

echo
if [ "$status" -eq 0 ]; then
  echo "Float text: every case is the shortest decimal that reads back, in"
  echo "Crystal's notation, and the check fails in both directions."
else
  echo "Float text: something above failed."
fi
exit "$status"
