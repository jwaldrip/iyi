#!/usr/bin/env bash
# Drives `iyi test` — the verify loop with no framework (AI_FIRST.md §2 #4).
#
#     bash bench/test_verb.sh
#
# A test is a plain iyi program that exits non-zero to fail. Four steps,
# and every one is a failure proof of a different kind, because a test
# runner's whole job is telling the four verdicts apart:
#
#   1. Passing tests: exit 0, and `--json` reports them as data.
#   2. A failing test: exit 1, the file named, its own output shown.
#   3. A test that does not build: a failure that says so, not a crash.
#   4. A test that hangs: killed at the deadline and named, because a
#      harness that can hang is not a harness.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
WORK="$(mktemp -d)"

cd "$WORK" || exit 1
step() { echo "== $1"; }

cat > math_test.iyi <<'IYI'
def check(name : String, ok : Bool) : Nil
  return if ok
  puts "FAIL: #{name}"
  __iyi_exit(1)
end

check("adds", 2 + 2 == 4)
check("concats", "a" + "b" == "ab")
IYI

step "passing tests exit 0, and --json is data"
"$IYI" test --json . > run.json 2>&1 || { cat run.json; exit 1; }
grep -Eq '"status": ?"pass"' run.json || { echo "no pass in the report:"; cat run.json; exit 1; }
grep -Eq '"failed": ?0' run.json || { echo "a passing run reported failures:"; cat run.json; exit 1; }

step "a failing test names itself and its evidence"
printf 'puts "the evidence line"\n__iyi_exit(1)\n' > broken_test.iyi
"$IYI" test . > run.txt 2>&1
[ $? -eq 1 ] || { echo "a failing test did not fail the run:"; cat run.txt; exit 1; }
grep -q 'broken_test.iyi: fail' run.txt || { echo "the failing file is unnamed:"; cat run.txt; exit 1; }
grep -q 'the evidence line' run.txt || { echo "the test's own output is missing:"; cat run.txt; exit 1; }
rm broken_test.iyi

step "a test that does not build is a verdict, not a crash"
printf 'this is not iyi\n' > syntax_test.iyi
"$IYI" test . > build.txt 2>&1
[ $? -eq 1 ] || { echo "an unbuildable test passed:"; cat build.txt; exit 1; }
grep -q 'syntax_test.iyi: does not build' build.txt || { echo "the verdict is wrong:"; cat build.txt; exit 1; }
rm syntax_test.iyi

step "a hanging test is killed at the deadline"
printf 'while true\nend\n' > hang_test.iyi
timeout 30 "$IYI" test --timeout 2 . > hang.txt 2>&1
status=$?
[ $status -eq 1 ] || { echo "the hang was not a failure (exit $status, 124 is the harness hanging):"; cat hang.txt; exit 1; }
grep -q 'hang_test.iyi: hung' hang.txt || { echo "the hang is unnamed:"; cat hang.txt; exit 1; }

echo "workdir $WORK"
echo "test verb gate: every step held"
exit 0
