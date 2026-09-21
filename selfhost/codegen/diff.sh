#!/usr/bin/env bash
# The iyi-written codegen slice against the current compiler, by what the
# programs do rather than by what they emit.
#
# Every other slice diffs an artifact: a token stream, a tree, a
# declaration, a type. Two independent backends do not write the same
# LLVM IR, and diffing the text would measure spelling. So each fixture
# ends in `__iyi_exit`, both compilers turn it into an executable, and
# this compares the status the two processes exit with. That is the one
# observable both can be asked for without a runtime underneath the port.
#
# A fixture that exits 0 either way would pass for free, so a fixture is
# required to exit non-zero and the gate says so rather than counting it.
set -u
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export LIBRARY_PATH=/opt/homebrew/opt/bdw-gc/lib

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -x "$REPO/bin/iyi" ] || { echo "  no $REPO/bin/iyi: run make first"; exit 1; }
command -v clang > /dev/null || { echo "  no clang: the emitted IR cannot be assembled"; exit 1; }

IYI_CACHE_DIR="$WORK/iyi" IYI_PATH="$REPO/src:$REPO/selfhost" \
  "$REPO/bin/iyi" build -o "$WORK/emit" "$HERE/emit.iyi" > "$WORK/build.log" 2>&1 || {
  echo "  the port does not build:"
  grep -aoE "Error[^\"]{0,120}" "$WORK/build.log" | head -3 | sed 's|^|    |'
  exit 1
}

fixtures=("$HERE"/fixtures/*.iyi)
[ "$#" -gt 0 ] && fixtures=("$@")

agree=0
differ=0
for fixture in "${fixtures[@]}"; do
  name="$(basename "$fixture")"

  # The oracle: the current compiler builds it and it runs.
  IYI_CACHE_DIR="$WORK/iyi" "$REPO/bin/iyi" build -o "$WORK/oracle" "$fixture" \
    > "$WORK/oracle.log" 2>&1 || {
    echo "  $name: the current compiler does not build it"
    differ=$((differ + 1)); continue
  }
  "$WORK/oracle" > "$WORK/oracle.out" 2>/dev/null; oracle_status=$?

  # The port: emit IR, assemble it, and run that.
  "$WORK/emit" "$fixture" > "$WORK/out.ll" 2> "$WORK/emit.err" || {
    echo "  $name: the port did not emit"; differ=$((differ + 1)); continue
  }
  clang -Wno-override-module -o "$WORK/port" "$WORK/out.ll" > "$WORK/clang.log" 2>&1 || {
    echo "  $name: the emitted IR does not assemble:"
    grep -aoE "error:.{0,100}" "$WORK/clang.log" | head -3 | sed 's|^|    |'
    differ=$((differ + 1)); continue
  }
  "$WORK/port" > "$WORK/port.out" 2>/dev/null; port_status=$?

  if [ "$oracle_status" -eq 0 ] && [ ! -s "$WORK/oracle.out" ]; then
    echo "  $name: exits 0 and prints nothing, which any emitter passes"
    differ=$((differ + 1)); continue
  fi
  if [ "$oracle_status" -ne "$port_status" ]; then
    differ=$((differ + 1))
    echo "  DIFFERS $name: the current compiler exits $oracle_status, the port $port_status"
    continue
  fi
  if ! diff -q "$WORK/oracle.out" "$WORK/port.out" > /dev/null; then
    differ=$((differ + 1))
    echo "  DIFFERS $name: same status, different output:"
    diff "$WORK/oracle.out" "$WORK/port.out" | head -4 | sed 's|^|    |'
    continue
  fi
  agree=$((agree + 1))
  if [ -s "$WORK/oracle.out" ]; then
    echo "  $name agrees: exit $oracle_status, $(wc -c < "$WORK/oracle.out" | tr -d ' ') bytes out"
  else
    echo "  $name agrees: exit $oracle_status"
  fi
done

echo "  agree $agree, differ $differ"
# Nothing compared is a failure, not a pass.
[ "$differ" -eq 0 ] && [ "$agree" -gt 0 ]
