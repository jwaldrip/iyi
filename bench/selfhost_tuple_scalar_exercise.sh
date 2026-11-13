#!/usr/bin/env bash
# Scalar tuple indexing against the hosted typed dump. Range indexing is later.
# Expectations are hosted's dump, not positions guessed from the source.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"
export IYI_PATH="$REPO/src"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export LIBRARY_PATH="${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}"
IYI="${IYI_COMPILER:-/Users/jwaldrip/checkouts/iyi-s1t/.build/iyi}"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "${CRYSTAL:-crystal}" build -Di_know_what_im_doing -o "$WORK/oracle" bench/selfhost_typed_oracle.cr > "$WORK/oracle.build" 2>&1 || { cat "$WORK/oracle.build"; exit 1; }
"$IYI" build -o "$WORK/typed" src/compiler/tools/typed_dump.iyi > "$WORK/typed.build" 2>&1 || { cat "$WORK/typed.build"; exit 1; }
fixture="$REPO/bench/fixtures/sem_bodies_tuple_scalar.iyi"
"$WORK/oracle" "$fixture" > "$WORK/hosted" 2> "$WORK/hosted.err" || { echo ORACLE; cat "$WORK/hosted.err"; exit 1; }
"$WORK/typed" "$fixture" "$REPO/src" > "$WORK/port" 2> "$WORK/port.err" || { echo PORT; cat "$WORK/port.err"; exit 1; }
# Hosted's actual call lines (s1d24 gate log), not the old guessed positions.
for expected in '30:10 Call Int32' '31:13 Call Int32' '32:12 Call UInt8' '33:10 Call Nil' '34:9 Call Int32'; do
  grep -Fx "$expected" "$WORK/hosted" || { echo "HOSTED missing $expected"; cat "$WORK/hosted"; exit 1; }
  grep -Fx "$expected" "$WORK/port" || { echo "PORT missing $expected"; cat "$WORK/port"; exit 1; }
done
if ! diff -q "$WORK/hosted" "$WORK/port" >/dev/null; then
  echo "scalar tuple dump differs from hosted"
  diff -u "$WORK/hosted" "$WORK/port"
  exit 1
fi
echo "sem_bodies_tuple_scalar.iyi matches hosted node by node"
