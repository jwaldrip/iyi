#!/usr/bin/env bash
# A property setter has no declared return. Its call type is the assigned value.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"
export IYI_PATH="$REPO/src"
IYI="${IYI_COMPILER:-/Users/jwaldrip/.local/state/ovnfs/uppers/int-next2/.build/iyi}"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "${CRYSTAL:-crystal}" build -Di_know_what_im_doing -o "$WORK/oracle" bench/selfhost_typed_oracle.cr > "$WORK/oracle.build" 2>&1 || { cat "$WORK/oracle.build"; exit 1; }
"$IYI" build -o "$WORK/native" src/compiler/tools/compile_native.iyi > "$WORK/native.build" 2>&1 || { cat "$WORK/native.build"; exit 1; }
fixture="$REPO/bench/fixtures/bodies_setter_value.iyi"
"$WORK/oracle" "$fixture" > "$WORK/hosted"
IYI_PATH="$REPO/src" "$WORK/native" "$fixture" -o "$WORK/out" --pipeline typed --prelude --probe-phase --keep-going > "$WORK/probe" 2>&1 || true
names="$WORK/out.names"
[ -f "$names" ] || { echo 'PORT WROTE NO NAMES'; cat "$WORK/probe"; exit 1; }
grep -Fx '*Fiber#next_run=<Nil>:Nil' "$names" || { echo PORT; cat "$names"; exit 1; }
grep -Fx '*Fiber#next_run=<Fiber>:Fiber' "$names" || { echo PORT; cat "$names"; exit 1; }
if grep -F 'next_run=<(Fiber | Nil)>' "$names"; then
  echo 'Setter still named by its declared union' >&2
  exit 1
fi
grep -F 'Call Nil' "$WORK/hosted"
grep -F 'Call Fiber' "$WORK/hosted"
