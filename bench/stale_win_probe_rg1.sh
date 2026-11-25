#!/usr/bin/env bash
# Probe: why RG1's second compiler build cannot find llvm's .lib on Windows.
# Probe only.
set -uo pipefail

REPO="$(cygpath -m "$(cd "$(dirname "$0")/.." && pwd)")"
echo "== environment"
echo "CRYSTAL_LIBRARY_PATH=${CRYSTAL_LIBRARY_PATH:-}"
echo "LLVM_VERSION=${LLVM_VERSION:-}"
echo "LIB=${LIB:-}" | tr ';' '\n' | head -20
echo "== the bootstrap package's lib"
ls -la "$(cygpath -u "${CRYSTAL_LIBRARY_PATH:-/nonexistent}")" 2>&1 | head -40
echo "== .build in the checkout"
ls -la "$REPO/.build" | head -40
echo "== llvm*.lib in the places that hold libraries"
find "$(cygpath -u "${CRYSTAL_LIBRARY_PATH:-/nonexistent}")" "/c/Program Files/LLVM" "/c/Program Files/Microsoft Visual Studio/18/Enterprise/VC/Tools/Llvm" -maxdepth 3 -iname 'llvm*.lib' 2>/dev/null | head -10
sed -n 1,40p "$REPO/bin/crystal.ps1" 2>/dev/null | head -60

WORK="$(cygpath -m "$(mktemp -d /tmp/rg1-probe.XXXXXX)")"
copy="$WORK/rg1"
mkdir -p "$copy"
(cd "$REPO" && find . \( -name .git -o -name .build \) -prune -o ! -type l ! -type d -print0 | tar --null -T - -cf -) | (cd "$copy" && tar -xf -)
mkdir -p "$copy/.build"
cp "$REPO/.build/crystal.exe" "$REPO/.build/LLVM-C.dll" "$copy/.build/"
echo "== make in the copy (as RG1 does)"
make -C "$copy" -f Makefile.win iyi FLAGS="" IYI_CONFIG_BUILD_COMMIT=0000000 2>&1 | tail -15
echo "make exit: ${PIPESTATUS[0]}"
echo "== make in the copy, with the whole .build copied"
cp -r "$REPO/.build/." "$copy/.build/" 2>&1 | tail -3
rm -f "$copy/.build/iyi.exe"
make -C "$copy" -f Makefile.win iyi FLAGS="" IYI_CONFIG_BUILD_COMMIT=0000000 2>&1 | tail -15
echo "make exit: ${PIPESTATUS[0]}"
rm -rf "$WORK"
