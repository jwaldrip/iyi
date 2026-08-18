#!/usr/bin/env bash
# Fails when an iyi program grows a new external dependency.
#
# Every symbol an iyi program leaves undefined is something the machine has to
# provide, and III.9 measured that list at seven. This checks it rather than
# asserting it: build every sample, read the undefined symbols out of each
# binary, and compare the union against the list below.
#
#     bash bench/dependency_floor.sh
#
# A new symbol is not automatically wrong. It is a dependency being added, which
# is a decision (III.10), and the way to record the decision is to add it here
# in the same commit that causes it. What this refuses is the version where a
# library arrives with a feature and nobody notices until somebody tries to
# build on a machine without it.
#
# Needs `make` for `bin/iyi`, and `nm`. Exits non-zero if the floor moved.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# The floor, as measured. Four allocator entry points and three libc calls.
ALLOWED="GC_init GC_malloc GC_malloc_atomic GC_realloc exit memset write"

# `nm -u` differs by platform: Mach-O prefixes an underscore, ELF appends a
# glibc version to some names. Normalise both to a bare symbol name.
symbols() {
  nm -u "$1" 2>/dev/null |
    sed -e 's/^ *//' -e 's/^U  *//' -e 's/@.*$//' |
    awk '{ print $NF }' |
    sed -e 's/^_//' |
    grep -v '^$' |
    sort -u
}

status=0
found="$WORK/found"
: >"$found"

for source in "$REPO"/samples/iyi/*.iyi; do
  sample="$(basename "$source" .iyi)"
  if ! "$IYI" build -o "$WORK/$sample" "$source" >"$WORK/$sample.log" 2>&1; then
    echo "$sample: build failed"
    tail -5 "$WORK/$sample.log"
    status=1
    continue
  fi
  symbols "$WORK/$sample" >"$WORK/$sample.syms"
  cat "$WORK/$sample.syms" >>"$found"
  printf '%-12s %s\n' "$sample" "$(tr '\n' ' ' <"$WORK/$sample.syms")"
done

if [ "$status" -ne 0 ]; then
  echo
  echo "a sample did not build, so the floor was not measured"
  exit 1
fi

sort -u "$found" >"$WORK/union"
printf '%s\n' $ALLOWED | sort -u >"$WORK/allowed"

added="$(comm -23 "$WORK/union" "$WORK/allowed")"
removed="$(comm -13 "$WORK/union" "$WORK/allowed")"

echo
if [ -n "$added" ]; then
  echo "THE DEPENDENCY FLOOR MOVED. These are new:"
  printf '  %s\n' $added
  echo
  echo "Each one is a library the machine now has to provide. If that is the"
  echo "decision, add it to ALLOWED in this script and say why in the commit"
  echo "(SPEC.md III.10). If it is not, it arrived by accident, which is what"
  echo "this check exists to catch."
  status=1
fi

if [ -n "$removed" ]; then
  echo "The floor got lower, and this script is out of date. Gone:"
  printf '  %s\n' $removed
  echo "Remove them from ALLOWED so the check keeps its teeth."
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "the floor holds: $(wc -l <"$WORK/union" | tr -d ' ') symbols, all of them expected"
fi

exit $status
