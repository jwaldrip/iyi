#!/usr/bin/env bash
set -eu
repo="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
export IYI_PATH="$repo/src"
"$repo/bin/iyi" build -o "$work/probe" "$repo/bench/diagnostic_untyped_probe.iyi" > "$work/build.log" 2>&1
if [ "$(uname -s)" = Darwin ]; then
  codesign -v --strict "$work/probe"
fi
"$work/probe" > "$work/actual"
awk '/^expected argument/ { exit } { print }' "$work/actual" > "$work/untyped"
printf '%s\n' "no overload matches 'consume' with type fresh" '' 'Overloads are:' ' - consume(value : String)' > "$work/expected"
cmp "$work/expected" "$work/untyped"
"$repo/bin/iyi" run "$repo/bench/fixtures/diagnostic_typed_mismatch.iyi" > "$work/hosted" 2>&1 && exit 1
awk '/^Error: / { sub(/^Error: /, ""); found=1 } found { print }' "$work/hosted" > "$work/hosted.error"
awk '/^expected argument/ { found=1 } found { print }' "$work/actual" > "$work/typed.error"
cmp "$work/hosted.error" "$work/typed.error"
echo 'untyped fallback and hosted typed diagnostic: pass'
