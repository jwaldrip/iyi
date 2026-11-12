#!/usr/bin/env bash
# The inline asm gate (SPEC 2.2, slice C4).
#
# Usage: bench/native_asm_exercise.sh aarch64
#
# 1. Builds the driver and line B's parse tool from the source.
# 2. Runs line B's parser over every tracked iyi file under src/. Its verdict
#    goes into the report the inventory reads. A file that holds asm( is read
#    by the inventory's scanner whatever the parser said: the parser does not
#    read asm expressions.
# 3. Inventories every asm(...) expression per target flag set, and reconciles
#    the count with git grep: each line that names asm( is an expression or a
#    named non-expression (a comment, a string, or an identifier such as
#    inline_asm(). No row may come from a file that fails to scan.
# 4. For every aarch64 template, on darwin and on Linux, the assembler's bytes
#    and relocations equal the oracle's. The oracle is the same template in a
#    naked function, built by ./bin/iyi build --cross-compile for that triple.
#    Mach-O is read by C1's reader, ELF by the driver's own reader. The twelve
#    templates with no adrp are compared on both triples (step 4b); the four
#    adrp templates use a page relocation one format spells, so each is compared
#    on the triple that spells it.
# 5. A template or constraint outside the supported set is refused by name.
# 6. otool -L on the driver shows /usr/lib/libSystem.B.dylib alone (macOS).
# 7. Mutation proofs: each must be caught. A patch whose text is absent, or that
#    leaves the text unchanged, is refused, and the proof fails.
#
# Jobs: native-linux runs every step (both formats compare on Linux; otool is
# skipped there). native-darwin reruns it, so step 6 runs on macOS.
#
# Needs a built compiler (`make`), line B's parser and python3.

set -u

arch="${1:-}"
if [ "$arch" != aarch64 ]; then
  echo "usage: $0 aarch64" >&2
  exit 2
fi

root="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
cd "$root" || exit 1

iyi=./bin/iyi
src_driver=src/compiler/tools/native_asm.iyi
src_asm=src/compiler/native/aarch64/asm.iyi
parse_src=src/compiler/tools/parse.iyi
fixtures=bench/fixtures/native_asm
triples="aarch64-apple-darwin aarch64-linux-gnu"

work="$(mktemp -d "${TMPDIR:-/tmp}/native_asm.XXXXXX")" || exit 1
restore=""
backup=""
cleanup() {
  if [ -n "$restore" ] && [ -n "$backup" ]; then
    cp "$backup" "$restore"
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

failures=0
fail() {
  echo "   $*"
  failures=$((failures + 1))
}

# build_driver: builds native_asm from the current source into $work/bin.
build_driver() {
  mkdir -p "$work/bin"
  "$iyi" build -o "$work/bin/native_asm" "$src_driver" >"$work/build-driver.log" 2>&1
}

echo "== 1. build the driver and line B's parse tool from the source"
if ! build_driver; then
  tail -n 20 "$work/build-driver.log"
  fail "the driver does not build"
  echo "== SOME NATIVE_ASM CHECKS FAILED"
  exit 1
fi
cp "$work/bin/native_asm" "$work/bin/native_asm.good"
if ! "$iyi" build -o "$work/bin/parse-tool" "$parse_src" >"$work/build-parse.log" 2>&1; then
  tail -n 20 "$work/build-parse.log"
  fail "the parse tool does not build"
  echo "== SOME NATIVE_ASM CHECKS FAILED"
  exit 1
fi

echo "== 2. line B's parser over every tracked iyi file under src"
git ls-files 'src/*.iyi' 'src/**/*.iyi' | sort -u >"$work/files.txt"
: >"$work/parse-report.tsv"
while IFS= read -r file; do
  out="$("$work/bin/parse-tool" "$file" 2>&1)"
  status=$?
  if [ "$status" -eq 0 ]; then
    printf '%s\tparsed\n' "$file" >>"$work/parse-report.tsv"
  else
    reason="$(printf '%s\n' "$out" | grep -m 1 -E 'Syntax error|panic' | tr '\t' ' ')"
    [ -n "$reason" ] || reason="exit $status"
    printf '%s\tscanned\t%s\n' "$file" "$reason" >>"$work/parse-report.tsv"
  fi
done <"$work/files.txt"
echo "   files: $(wc -l <"$work/files.txt" | tr -d ' ')"
echo "   parsed by line B: $(awk -F'\t' '$2 == "parsed"' "$work/parse-report.tsv" | wc -l | tr -d ' ')"
echo "   refused by line B: $(awk -F'\t' '$2 == "scanned"' "$work/parse-report.tsv" | wc -l | tr -d ' ')"

echo "== 3. inventory: every asm(...) expression per target, against git grep"
if ! "$work/bin/native_asm" inventory "$work/parse-report.tsv" >"$work/inventory.txt" 2>"$work/inventory.err"; then
  tail -n 3 "$work/inventory.err"
  fail "the inventory failed"
fi
grep -E '^(SUMMARY|MNEMONICS|CENSUS)' "$work/inventory.txt"
echo "   scanned files (asm text present):"
grep '^SCANNED' "$work/inventory.txt" | awk -F'\t' '{print "     " $2 "  " $3}' | sort -u
echo "   refused by a {% raise %}: $(grep -c '^REFUSED' "$work/inventory.txt")"
echo "   errors: $(grep -c '^ERROR' "$work/inventory.txt")"
if grep -q '^ERROR' "$work/inventory.txt"; then
  grep '^ERROR' "$work/inventory.txt" | head -n 5
  fail "the inventory reports errors"
fi
echo "   non-expression asm( lines:"
grep '^NOT_EXPRESSION' "$work/inventory.txt" | awk -F'\t' '{print "     " $2 "  " $3}'

gg_lines="$(git grep -n 'asm(' -- 'src/*.iyi' 'src/**/*.iyi' | wc -l | tr -d ' ')"
substring_lines="$(grep '^CENSUS' "$work/inventory.txt" | sed -e 's/.*substring_lines=//')"
expressions="$(grep '^SUMMARY' "$work/inventory.txt" | head -n 1 | sed -e 's/.*expressions=//' -e 's/\t.*//')"
not_expressions="$(grep -c '^NOT_EXPRESSION' "$work/inventory.txt")"
echo "   git grep asm( lines under src/*.iyi: $gg_lines"
echo "   inventory substring lines: $substring_lines"
echo "   expression lines: $expressions, non-expression lines: $not_expressions"
if [ "$substring_lines" != "$gg_lines" ]; then
  fail "the inventory counts $substring_lines asm( lines, git grep finds $gg_lines"
fi
if [ $((expressions + not_expressions)) != "$gg_lines" ]; then
  fail "expressions and non-expressions do not account for every line"
fi

echo "== 4. aarch64 templates: bytes and relocations equal the oracle's"
for pair in "macho aarch64-apple-darwin oracle-macho" "elf aarch64-linux-gnu oracle-elf"; do
  set -- $pair
  fmt=$1
  triple=$2
  dump=$3
  src="$work/oracle-$fmt.iyi"
  obj="$work/oracle-$fmt.o"
  "$work/bin/native_asm" oracle-source "$work/inventory.txt" "$triple" >"$src" 2>"$work/oracle-$fmt.src.err"
  if ! "$iyi" build --cross-compile --target "$triple" -o "$obj" "$src" >"$work/oracle-$fmt.build.log" 2>&1; then
    grep -v 'ld: warning' "$work/oracle-$fmt.build.log" | tail -n 8
    fail "the oracle does not build for $triple"
    continue
  fi
  "$work/bin/native_asm" "$dump" "$obj" >"$work/oracle-$fmt.txt" 2>"$work/oracle-$fmt.dump.err" || fail "the oracle reader fails on $triple"
  "$work/bin/native_asm" cases "$work/inventory.txt" "$triple" >"$work/cases-$fmt.txt" 2>"$work/cases-$fmt.err" || fail "the assembler fails for $triple"
  if grep -q '^REFUSED' "$work/cases-$fmt.txt"; then
    grep '^REFUSED' "$work/cases-$fmt.txt"
    fail "a $triple template is refused by the assembler"
  fi
  sort "$work/oracle-$fmt.txt" >"$work/oracle-$fmt.sorted"
  sort "$work/cases-$fmt.txt" >"$work/cases-$fmt.sorted"
  funcs="$(grep -c '^FUNC' "$work/oracle-$fmt.sorted")"
  relocs="$(grep -c '^RELOC' "$work/oracle-$fmt.sorted")"
  if cmp -s "$work/oracle-$fmt.sorted" "$work/cases-$fmt.sorted"; then
    echo "   $triple: $funcs functions and $relocs relocations equal the oracle's"
  else
    diff "$work/oracle-$fmt.sorted" "$work/cases-$fmt.sorted" | head -n 12
    fail "the assembler's output differs from the oracle for $triple"
  fi
done
echo "== 4b. the templates both formats accept: each equals the oracle on both triples"
"$work/bin/native_asm" oracle-source "$work/inventory.txt" shared >"$work/shared.iyi" 2>"$work/shared.src.err" || fail "the shared oracle source fails"
"$work/bin/native_asm" cases "$work/inventory.txt" shared | sort >"$work/shared-cases.sorted" 2>"$work/shared.cases.err" || fail "the assembler fails on the shared templates"
for pair in "macho aarch64-apple-darwin oracle-macho" "elf aarch64-linux-gnu oracle-elf"; do
  set -- $pair
  fmt=$1
  triple=$2
  dump=$3
  obj="$work/shared-$fmt.o"
  if ! "$iyi" build --cross-compile --target "$triple" -o "$obj" "$work/shared.iyi" >"$work/shared-$fmt.build.log" 2>&1; then
    grep -v 'ld: warning' "$work/shared-$fmt.build.log" | tail -n 8
    fail "the shared oracle does not build for $triple"
    continue
  fi
  "$work/bin/native_asm" "$dump" "$obj" | sort >"$work/shared-$fmt.sorted" || fail "the oracle reader fails on the shared set for $triple"
  if cmp -s "$work/shared-$fmt.sorted" "$work/shared-cases.sorted"; then
    echo "   $triple: $(grep -c '^FUNC' "$work/shared-$fmt.sorted") shared functions and $(grep -c '^RELOC' "$work/shared-$fmt.sorted") relocations equal the oracle's"
  else
    diff "$work/shared-$fmt.sorted" "$work/shared-cases.sorted" | head -n 12
    fail "the shared templates differ from the oracle on $triple"
  fi
done

echo "== 5. refusals: outside the supported set, refused by name"
# The fixtures end in .tmpl, not .s: the tree ignores *.s, and an ignored
# fixture is on one machine only.
for fixture in "$fixtures"/refuse/*.tmpl; do
  name="$(basename "$fixture")"
  expect="$(awk -F'\t' -v f="$name" '$1 == f { print $2 }' "$fixtures/refuse/EXPECT.tsv")"
  got="$("$work/bin/native_asm" refuse "$fixture" 2>&1)"
  case "$got" in
    REFUSED*"$expect"*) echo "   refused: $name" ;;
    *) fail "$name: expected a refusal containing '$expect', got: $got" ;;
  esac
done
"$work/bin/native_asm" constraints "$fixtures/constraints.tsv" >"$work/constraints.out" 2>"$work/constraints.err" || fail "the constraint fixtures fail to run"
n=0
while IFS="$(printf '\t')" read -r kind item expect; do
  n=$((n + 1))
  actual="$(sed -n "${n}p" "$work/constraints.out")"
  case "$expect" in
    ACCEPTED)
      case "$actual" in
        ACCEPTED*) ;;
        *) fail "constraint $kind $item: expected ACCEPTED, got: $actual" ;;
      esac
      ;;
    REFUSED:*)
      sub="${expect#REFUSED:}"
      case "$actual" in
        REFUSED*"$sub"*) ;;
        *) fail "constraint $kind $item: expected a refusal containing '$sub', got: $actual" ;;
      esac
      ;;
  esac
done <"$fixtures/constraints.tsv"
echo "   constraint fixtures checked: $n"

echo "== 6. the driver links libSystem alone (macOS)"
if [ "$(uname -s)" = Darwin ]; then
  deps="$(otool -L "$work/bin/native_asm" | tail -n +2 | awk '{ print $1 }')"
  echo "   $deps"
  if [ "$deps" != "/usr/lib/libSystem.B.dylib" ]; then
    fail "the driver links more than libSystem: $deps"
  fi
else
  echo "   skipped: otool is macOS only; the darwin job runs this step"
fi

# prove_mutation LABEL FILE OLD NEW CHECK...: replaces the first OLD in FILE with
# NEW, runs CHECK, and requires it to fail. A patch whose OLD is absent, or whose
# NEW leaves the text unchanged, changes nothing and is refused. Restores FILE
# on every exit path.
prove_mutation() {
  label=$1
  file=$2
  old=$3
  new=$4
  shift 4
  backup="$work/mutation-$RANDOM.bak"
  cp "$file" "$backup" || return 1
  restore="$file"
  python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text or old == new:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
  patched=$?
  if [ "$patched" -eq 3 ]; then
    cp "$backup" "$file"
    restore=""
    fail "PATCH CHANGED NOTHING: '$label' found no text to change"
    return 1
  fi
  if [ "$patched" -ne 0 ]; then
    cp "$backup" "$file"
    restore=""
    fail "could not apply '$label'"
    return 1
  fi
  if "$@" >"$work/mutation-check.log" 2>&1; then
    fail "NOT caught: $label"
  else
    echo "   caught: $label"
  fi
  cp "$backup" "$file"
  restore=""
  return 0
}

# expect_refused_patch LABEL FILE OLD NEW: a patch that changes nothing must be
# refused by the helper. Passes when the helper refuses it, and leaves FILE as it was.
expect_refused_patch() {
  label=$1
  file=$2
  old=$3
  new=$4
  before="$(cksum <"$file")"
  python3 - "$file" "$old" "$new" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
if old not in text or old == new:
    sys.exit(3)
open(path, "w", encoding="utf-8").write(text.replace(old, new, 1))
PY
  status=$?
  after="$(cksum <"$file")"
  if [ "$status" -eq 3 ] && [ "$before" = "$after" ]; then
    echo "   refused: $label"
  else
    fail "a patch that changes nothing was not refused: $label"
  fi
}

# check_bytes: rebuilds the driver from the source as it now stands, and
# requires its cases to equal the oracle's on both triples. Fails when they differ.
check_bytes() {
  build_driver || return 1
  for pair in "macho aarch64-apple-darwin" "elf aarch64-linux-gnu"; do
    set -- $pair
    "$work/bin/native_asm" cases "$work/inventory.txt" "$2" | sort >"$work/mut-$1.txt" || return 1
    cmp -s "$work/mut-$1.txt" "$work/oracle-$1.sorted" || return 1
  done
  return 0
}

echo "== 7. mutation proofs"
prove_mutation "the @PAGE relocation given the @PAGEOFF kind" "$src_asm" \
  "RelocKind::A64AdrpPage21" "RelocKind::A64AddLo12" check_bytes
prove_mutation "the @PAGEOFF relocation given the @PAGE kind" "$src_asm" \
  "RelocKind::A64AddLo12" "RelocKind::A64AdrpPage21" check_bytes
prove_mutation "the Rn field shifted one place too far in the encoder" "$src_asm" \
  "reg.to_i64 * 32_i64" "reg.to_i64 * 64_i64" check_bytes
expect_refused_patch "a patch whose text is absent" "$src_asm" \
  "NO_SUCH_TEXT_IN_THE_ASSEMBLER" "x"
expect_refused_patch "a patch that leaves the text unchanged" "$src_asm" \
  "reg.to_i64 * 32_i64" "reg.to_i64 * 32_i64"

# The driver built from the unmutated source serves the rest of the run.
cp "$work/bin/native_asm.good" "$work/bin/native_asm"

if [ "$failures" -eq 0 ]; then
  echo "== ALL NATIVE_ASM CHECKS PASSED"
  exit 0
fi
echo "== SOME NATIVE_ASM CHECKS FAILED"
exit 1
