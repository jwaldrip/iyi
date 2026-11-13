#!/usr/bin/env bash
# Compare scalar tuple indexing with hosted. Range indexing is intentionally absent.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-/Users/jwaldrip/.local/state/ovnfs/uppers/s2a25-closure-int/.build/iyi}"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "${CRYSTAL:-crystal}" build -Di_know_what_im_doing -o "$WORK/oracle" bench/selfhost_typed_oracle.cr > "$WORK/oracle.build" 2>&1 || { cat "$WORK/oracle.build"; exit 1; }
"$IYI" build -o "$WORK/typed" src/compiler/tools/typed_dump.iyi > "$WORK/typed.build" 2>&1 || { cat "$WORK/typed.build"; exit 1; }
fixture="$REPO/bench/fixtures/sem_bodies_tuple_scalar.iyi"
"$WORK/oracle" "$fixture" > "$WORK/hosted"
"$WORK/typed" "$fixture" "$REPO/src" > "$WORK/port"
for expected in '5:9 Var Int32' '10:5 Call Int32' '15:5 Call UInt8' '20:5 Call Nil' '25:5 Call Int32'; do
  grep -Fx "$expected" "$WORK/hosted" || { echo "HOSTED"; cat "$WORK/hosted"; exit 1; }
  grep -Fx "$expected" "$WORK/port" || { echo "PORT"; cat "$WORK/port"; exit 1; }
done
