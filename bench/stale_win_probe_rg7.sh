#!/usr/bin/env bash
# Probe: bench/stale_reproducible.sh's RG7 loop for one program, with cmp's own
# account of where the two executables differ. Probe only.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(cygpath -m "$REPO")"
IYI="$(cygpath -m "${IYI:-$REPO/.build/iyi.exe}")"
PSEP=';'
export ZERO_AR_DATE=1
export SOURCE_DATE_EPOCH="$(git -C "$REPO" show -s --format=%ct HEAD 2>/dev/null || echo 0)"
export IYI_PATH="$REPO/src${PSEP}$REPO/samples/iyi"
export IYI_LIBRARY_PATH="$REPO/lib"
WORK="$(mktemp -d /tmp/stale-repro-work.XXXXXX)"
WORK="$(cygpath -m "$WORK")"
CACHE="$WORK/cache"
mkdir -p "$CACHE"
export IYI_CACHE_DIR="$CACHE"
echo "WORK=$WORK SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"

prog="$REPO/samples/iyi/${1:-hello.iyi}"
out="$WORK/prog_out.exe"
saved="$WORK/prog_t1"

rm -rf "$CACHE"/*
"$IYI" build --threads 1 -o "$out" "$prog"
cp "$out" "$saved"
ls -l "$out" "$saved"
cp "$out" "$WORK/first.exe"

rm -rf "$CACHE"/*
"$IYI" build --threads 8 -o "$out" "$prog"
ls -l "$out"

if cmp "$saved" "$out"; then
  echo "identical"
else
  echo "cmp -l: first 40 differing bytes (offset, octal, octal)"
  cmp -l "$saved" "$out" | head -40 || true
  echo "total differing bytes: $(cmp -l "$saved" "$out" | wc -l)"
fi
# The second build again to the same name, with the cache emptied, to see whether the second build of a name differs from the first by itself.
rm -rf "$CACHE"/*
"$IYI" build --threads 8 -o "$out" "$prog"
if cmp "$saved" "$out"; then echo "third build identical to the first"; else echo "third build differs from the first"; fi
rm -rf "$CACHE"/*
"$IYI" build --threads 1 -o "$out" "$prog"
if cmp "$saved" "$out"; then echo "fourth build (threads 1 again) identical to the first"; else echo "fourth build (threads 1 again) differs from the first"; fi
rm -rf "$WORK"
