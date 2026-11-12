#!/usr/bin/env bash
# Line A's corpora through line B's lexer, parser and declaration tools.
#
# Line A (upstream PR #104) measured its own lexer, parser and declaration
# tools on the samples, the prelude, std, the parser's own source and its
# fixtures. This gate runs line B's tools on the same corpora and prints agree
# and differ counts beside line A's measured figures. Agreement is per file:
# the tool's standard output is byte-identical to the hosted front end's
# output for that file, and the tool exits 0.
#
# The golden dumpers are the inline scripts the existing gates
# already use (bench/selfhost_lexer_exercise.sh, bench/selfhost_parser_exercise.sh
# and bench/selfhost_semantic_exercise.sh). They are extracted from those gates,
# not copied, so the comparison cannot drift from the gates' own oracles.
#
# The gate fails only when a corpus agrees on fewer files than its committed
# floor (the FLOOR table below). A corpus that gets better is reported so the
# floor can be raised; it does not fail.
#
#   bash bench/selfhost_linea_corpus_exercise.sh
#
# Environment (for the mutation proof only):
#   LINEA_FLOOR_BUMP=1   add one to every floor, so a healthy run must fail
#
# Output: "== N. <step>" lines, the agreement table, then
# "== ALL LINE A CORPUS CHECKS PASSED" or "== SOME LINE A CORPUS CHECKS FAILED".
# Exit status 0 or 1.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
LC_ALL=C
export LC_ALL
export IYI_CACHE_DIR="$WORK/cache"
status=0
RESULTS="$WORK/results.tsv"
: > "$RESULTS"

# The committed floors: files that agree per (tool, corpus). Raise them when the
# table shows a corpus getting better; never lower one.
floor_of() {
  case "$1:$2" in
    lexer:samples)         echo 28 ;;
    lexer:prelude)         echo 14 ;;
    lexer:std)             echo 119 ;;
    lexer:self)            echo 1 ;;
    lexer:fixtures)        echo 15 ;;
    parser:samples)        echo 0 ;;
    parser:prelude)        echo 4 ;;
    parser:std)            echo 0 ;;
    parser:self)           echo 0 ;;
    parser:fixtures)       echo 3 ;;
    declarations:samples)  echo 0 ;;
    declarations:prelude)  echo 10 ;;
    declarations:std)      echo 0 ;;
    declarations:self)     echo 0 ;;
    declarations:fixtures) echo 2 ;;
    *)                     echo 0 ;;
  esac
}

# Line A's measured figures from upstream PR #104 (their denominators where the
# PR states them; "n/a" where it did not measure the cell).
linea_figure() {
  case "$1:$2" in
    parser:samples)        echo "27 of 27" ;;
    parser:prelude)        echo "17 of 17" ;;
    parser:std)            echo "67 of 67" ;;
    parser:self)           echo "identical" ;;
    lexer:samples)         echo "6 agree (denominator not stated)" ;;
    declarations:samples)  echo "23 agree (denominator not stated)" ;;
    declarations:prelude)  echo "14 of 15" ;;
    declarations:std)      echo "31 of 35" ;;
    *)                     echo "n/a" ;;
  esac
}

extract_golden() {
  sed -n "/^cat <<'[A-Z_]*GOLDEN_SCRIPT'/,/^[A-Z_]*GOLDEN_SCRIPT\$/p" "$1" | sed '1d;$d' > "$2"
}

echo "== 1. Building line B's lexer, parser and declaration tools and their golden dumpers"
extract_golden "$REPO/bench/selfhost_lexer_exercise.sh" "$WORK/dump_lexer.cr"
extract_golden "$REPO/bench/selfhost_parser_exercise.sh" "$WORK/dump_parser.cr"
extract_golden "$REPO/bench/selfhost_semantic_exercise.sh" "$WORK/dump_decls.cr"
for pair in "$WORK/dump_lexer.cr" "$WORK/dump_parser.cr" "$WORK/dump_decls.cr"; do
  if [ ! -s "$pair" ]; then
    echo "  FAILED to extract a Crystal golden dumper from its gate: $pair"
    exit 1
  fi
done
"$IYI" build -o "$WORK/lexer" "$REPO/bench/selfhost_lexer_exercise.iyi" > "$WORK/lexer_build.log" 2>&1 \
  || { cat "$WORK/lexer_build.log"; echo "  FAILED to build the lexer tool"; exit 1; }
"$IYI" build -o "$WORK/parser" "$REPO/bench/selfhost_parser_exercise.iyi" > "$WORK/parser_build.log" 2>&1 \
  || { cat "$WORK/parser_build.log"; echo "  FAILED to build the parser tool"; exit 1; }
"$IYI" build -o "$WORK/decls" "$REPO/bench/selfhost_semantic_exercise.iyi" > "$WORK/decls_build.log" 2>&1 \
  || { cat "$WORK/decls_build.log"; echo "  FAILED to build the declaration tool"; exit 1; }
CRYSTAL_PATH="$REPO/src" "$REPO/bin/crystal" build -o "$WORK/golden_lexer" "$WORK/dump_lexer.cr" > "$WORK/golden_lexer.log" 2>&1 \
  || { cat "$WORK/golden_lexer.log"; echo "  FAILED to build the lexer golden dumper"; exit 1; }
CRYSTAL_PATH="$REPO/src" "$REPO/bin/crystal" build -o "$WORK/golden_parser" "$WORK/dump_parser.cr" > "$WORK/golden_parser.log" 2>&1 \
  || { cat "$WORK/golden_parser.log"; echo "  FAILED to build the parser golden dumper"; exit 1; }
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" CRYSTAL_PATH="$REPO/src" \
  "$CRYSTAL" build -Di_know_what_im_doing -o "$WORK/golden_decls" "$WORK/dump_decls.cr" > "$WORK/golden_decls.log" 2>&1 \
  || { cat "$WORK/golden_decls.log"; echo "  FAILED to build the declaration golden dumper"; exit 1; }
echo "  built: lexer, parser and declaration tools; three golden dumpers"

# One file: run line B's tool and the golden dumper, record agree or differ.
compare() {
  tool="$1"
  corpus="$2"
  rel="$3"
  case "$tool" in
    lexer)        mine="$WORK/lexer";  golden="$WORK/golden_lexer" ;;
    parser)       mine="$WORK/parser"; golden="$WORK/golden_parser" ;;
    declarations) mine="$WORK/decls";  golden="$WORK/golden_decls" ;;
  esac
  if "$mine" "$rel" > "$WORK/mine.out" 2> "$WORK/mine.err" \
     && IYI_PATH="$REPO/src" "$golden" "$rel" > "$WORK/golden.out" 2> "$WORK/golden.err" \
     && cmp -s "$WORK/mine.out" "$WORK/golden.out"; then
    verdict=agree
  else
    verdict=differ
  fi
  printf '%s\t%s\t%s\t%s\n' "$tool" "$corpus" "$rel" "$verdict" >> "$RESULTS"
}

echo
echo "== 2. Running every tool over every corpus, file by file"
corpora() {
  for f in samples/iyi/*.iyi; do printf 'samples\t%s\n' "$f"; done
  for f in src/iyi/*.iyi; do printf 'prelude\t%s\n' "$f"; done
  for f in src/std/*.iyi; do printf 'std\t%s\n' "$f"; done
  printf 'self\tsrc/compiler/syntax/parser.iyi\n'
  for f in bench/fixtures/linea/parser/*.iyi bench/fixtures/linea/semantic/*.iyi; do printf 'fixtures\t%s\n' "$f"; done
}
corpora > "$WORK/corpora.tsv"
while IFS="$(printf '\t')" read -r corpus rel; do
  for tool in lexer parser declarations; do
    compare "$tool" "$corpus" "$rel"
  done
done < "$WORK/corpora.tsv"
echo "  $(wc -l < "$RESULTS" | tr -d ' ') tool-file runs"

echo
echo "== 3. Agreement per tool and corpus, beside line A's measured figures (PR #104)"
printf '  %-13s %-9s %6s %6s %6s %6s  %-6s  %s\n' tool corpus files agree differ floor verdict "line A (PR #104)"
fails=0
for tool in lexer parser declarations; do
  for corpus in samples prelude std self fixtures; do
    total=$(awk -F'\t' -v t="$tool" -v c="$corpus" '$1 == t && $2 == c' "$RESULTS" | wc -l | tr -d ' ')
    agree=$(awk -F'\t' -v t="$tool" -v c="$corpus" '$1 == t && $2 == c && $4 == "agree"' "$RESULTS" | wc -l | tr -d ' ')
    differ=$((total - agree))
    floor=$(floor_of "$tool" "$corpus")
    if [ "${LINEA_FLOOR_BUMP:-0}" = 1 ]; then
      floor=$((floor + 1))
    fi
    if [ "$total" -eq 0 ]; then
      verdict="empty"
    elif [ "$agree" -lt "$floor" ]; then
      verdict="BELOW"
      fails=$((fails + 1))
    elif [ "$agree" -gt "$floor" ]; then
      verdict="better"
    else
      verdict="ok"
    fi
    printf '  %-13s %-9s %6s %6s %6s %6s  %-6s  %s\n' "$tool" "$corpus" "$total" "$agree" "$differ" "$floor" "$verdict" "$(linea_figure "$tool" "$corpus")"
  done
done

echo
echo "== 4. Files that differ, by tool"
awk -F'\t' '$4 == "differ" { printf "  %-13s %-9s %s\n", $1, $2, $3 }' "$RESULTS"

echo
echo "== 5. Floor check"
if [ "$fails" -gt 0 ]; then
  echo "  $fails corpus cell(s) agree on fewer files than their committed floor"
  status=1
else
  echo "  every corpus meets its committed floor"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "== ALL LINE A CORPUS CHECKS PASSED"
else
  echo "== SOME LINE A CORPUS CHECKS FAILED"
fi
exit "$status"
