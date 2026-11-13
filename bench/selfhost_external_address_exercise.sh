#!/usr/bin/env bash
# Compare external-variable address typing and ordinary function refusal with hosted.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "${CRYSTAL:-crystal}" build -Di_know_what_im_doing -o "$WORK/oracle" bench/selfhost_typed_oracle.cr
bin/iyi build -o "$WORK/typed" src/compiler/tools/typed_dump.iyi
positive="$REPO/bench/fixtures/bodies_external_var_address.iyi"
negative="$REPO/bench/fixtures/bodies_pointer_function_call.iyi"
"$WORK/oracle" "$positive" > "$WORK/hosted"
"$WORK/typed" "$positive" "$REPO/src" > "$WORK/port"
for expected in '7:1 PointerOf Pointer(Int32)' '8:1 PointerOf Pointer(Pointer(UInt8))'; do
  grep -Fx "$expected" "$WORK/hosted"
  grep -Fx "$expected" "$WORK/port"
done
if "$WORK/oracle" "$negative" > "$WORK/invalid-hosted" 2>&1; then
  echo 'Hosted accepted pointerof an ordinary function call' >&2
  exit 1
fi
"$WORK/typed" "$negative" "$REPO/src" > "$WORK/invalid-port"
grep -F 'untyped: pointerof of' "$WORK/invalid-port"
if grep -F 'PointerOf Pointer(' "$WORK/invalid-port"; then
  echo 'Port accepted pointerof an ordinary function call' >&2
  exit 1
fi
