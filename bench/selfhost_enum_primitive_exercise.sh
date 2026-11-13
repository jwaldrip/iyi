#!/usr/bin/env bash
# Generated enum primitives have no written return annotation. Hosted and port
# must still type the primitive body as the enum base type.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "${CRYSTAL:-crystal}" build -Di_know_what_im_doing -o "$WORK/oracle" bench/selfhost_typed_oracle.cr > "$WORK/oracle.build" 2>&1 || { cat "$WORK/oracle.build"; exit 1; }
"$IYI" build -o "$WORK/typed" src/compiler/tools/typed_dump.iyi > "$WORK/typed.build" 2>&1 || { cat "$WORK/typed.build"; exit 1; }
fixture="$REPO/bench/fixtures/bodies_enum_primitive.iyi"
"$WORK/oracle" "$fixture" > "$WORK/hosted"
"$WORK/typed" "$fixture" "$REPO/src" > "$WORK/port"
for expected in '7:9 Call UInt8' '7:9 Var FiberState'; do
  grep -Fx "$expected" "$WORK/hosted" || { echo HOSTED; cat "$WORK/hosted"; exit 1; }
  grep -Fx "$expected" "$WORK/port" || { echo PORT; cat "$WORK/port"; exit 1; }
done
if grep -F 'primitive enum_value without a declared return type' "$WORK/port"; then
  echo 'Port still refused the generated enum primitive' >&2
  exit 1
fi
