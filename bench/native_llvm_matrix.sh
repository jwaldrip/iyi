#!/bin/sh
# Corpus matrix for the native LLVM round trip (SPEC 3.3, slice B2). For every program in
# samples/iyi, bench/std_*_exercise.iyi, bench/fixtures/cg_*.iyi and bench/fixtures/compile_*.iyi,
# and every target, it emits LLVM IR with the hosted compiler, round-trips it through iyi-ir and
# records a verdict. Each .ll is deleted once its verdict and coverage are taken, so only one
# program's IR is on disk at a time. Prints the per-target table, the refusal names and the
# coverage inventory. Not part of the gate: it is a measurement, and it needs ./bin/iyi and
# .build/iyi-ir already built.
set -u

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root" || exit 1
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin
export PATH
LIBRARY_PATH=${LIBRARY_PATH:-/opt/homebrew/opt/bdw-gc/lib}
export LIBRARY_PATH

IY=./bin/iyi
TOOL=${TOOL:-.build/iyi-ir}
SCR=${SCR:-/tmp/iyi-native-llvm-matrix}
TARGETS=${TARGETS:-"aarch64-apple-darwin aarch64-linux-gnu x86_64-linux-gnu x86_64-windows-msvc wasm32-wasi"}

rm -rf "$SCR"
mkdir -p "$SCR"
VERDICTS="$SCR/verdicts.tsv"
COVERAGE="$SCR/coverage.tsv"
: > "$VERDICTS"
: > "$COVERAGE"

PROGRAMS=$(ls samples/iyi/*.iyi bench/std_*_exercise.iyi bench/fixtures/cg_*.iyi bench/fixtures/compile_*.iyi 2>/dev/null)

for target in $TARGETS; do
  for program in $PROGRAMS; do
    base=$(basename "$program" .iyi)
    out="$SCR/$base-$target"
    emit=$("$IY" build --emit llvm-ir --cross-compile --target "$target" -o "$out" "$program" 2>&1)
    if [ ! -f "$out.ll" ]; then
      first=$(echo "$emit" | awk '/^Error:/ { print; f=1; exit } NF && !g { g=$0 } END { if (!f) print g }')
      printf '%s\t%s\tnot-emitted\t%s\n' "$target" "$program" "$first" >> "$VERDICTS"
      rm -f "$out" "$out".*
      continue
    fi
    result=$("$TOOL" roundtrip "$out.ll" 2>&1)
    first=$(echo "$result" | awk 'NF' | head -1)
    case "$first" in
      identical) verdict=identical ;;
      refused:*) verdict=refused ;;
      "refused by the translator"*) verdict=refused-by-translator ;;
      *) verdict=differs ;;
    esac
    detail=$(echo "$result" | awk 'NF' | head -3 | tr '\n' ' ' | cut -c1-400)
    printf '%s\t%s\t%s\t%s\n' "$target" "$program" "$verdict" "$detail" >> "$VERDICTS"
    "$TOOL" coverage "$out.ll" 2>/dev/null | awk -F'\t' -v t="$target" 'NF==4 && $1!="category" && $1!="entries_not_in_ir" {print t "\t" $0}' >> "$COVERAGE"
    rm -f "$out.ll" "$out" "$out".*
  done
done

echo "== per-target verdicts (programs x targets)"
echo "target	identical	differs	refused	refused-by-translator	not-emitted"
for target in $TARGETS; do
  awk -F'\t' -v t="$target" '
    $1 == t {
      n[$3]++
    }
    END {
      printf "%s\t%d\t%d\t%d\t%d\t%d\n", t, n["identical"]+0, n["differs"]+0, n["refused"]+0, n["refused-by-translator"]+0, n["not-emitted"]+0
    }' "$VERDICTS"
done

echo "== refusal names (count per target)"
awk -F'\t' '$3 == "refused" || $3 == "refused-by-translator" { print $1 "\t" $3 "\t" $4 }' "$VERDICTS" | sort | uniq -c

echo "== differences (first difference per program, darwin and others)"
awk -F'\t' '$3 == "differs" { print $1 "\t" $2 "\t" $4 }' "$VERDICTS" | sort | uniq -c | sort -rn | head -40

echo "== not emitted by the hosted compiler (its first error line)"
awk -F'\t' '$3 == "not-emitted" { print $1 "\t" $4 }' "$VERDICTS" | sort | uniq -c | sort -rn | head -40

echo "== coverage inventory over the corpus (all targets)"
echo "category	name	count	in_iyi_ir"
awk -F'\t' '
  {
    key = $2 "\t" $3
    count[key] += $5
    inir[key] = $4
  }
  END {
    for (k in count) printf "%s\t%d\t%s\n", k, count[k], inir[k]
  }' "$COVERAGE" | sort

echo "== programs read: $(awk -F'\t' '$1 == "aarch64-apple-darwin" { n++ } END { print n+0 }' "$VERDICTS") per target"
echo "== verdicts file: $VERDICTS"
