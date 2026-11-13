#!/usr/bin/env bash
# The self-host gate runner's own exercise (bench/selfhost_gates.sh). A copy of the runner
# runs in a scratch tree of stand-in gates, with a `uname` that answers for the host under
# test, so no real gate runs here.
#
#   bash bench/gates_runner_exercise.sh
#
# 1. On Darwin arm64 every gate runs: a failing typed-lowering gate fails the run.
# 2. On another host the gates in DARWIN_ARM64_GATES are named as skipped and are not run;
#    the verdict counts them; a failing gate outside the list still fails the run.
# 3. A name in DARWIN_ARM64_GATES with no gate file is refused.
# 4. Two shards run every gate exactly once between them.
set -u
cd "$(dirname "$0")/.." || exit 1

WORK=$(mktemp -d "${TMPDIR:-/tmp}/gates-runner.XXXXXX")
trap 'rm -rf "$WORK"' EXIT INT TERM
failed=0
fail() { echo "FAIL: $*"; failed=1; }

LISTED=$(sed -n 's/^DARWIN_ARM64_GATES="\(.*\)"$/\1/p' bench/selfhost_gates.sh)
[ -n "$LISTED" ] || { echo "FAIL: bench/selfhost_gates.sh has no DARWIN_ARM64_GATES line"; exit 1; }
listed_count=$(echo $LISTED | wc -w | tr -d ' ')
OTHERS="selfhost_semantic_exercise selfhost_types_exercise"

mkdir -p "$WORK/bin"
cat > "$WORK/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) echo "$FAKE_SYSTEM" ;;
  -m) echo "$FAKE_MACHINE" ;;
esac
EOF
chmod +x "$WORK/bin/uname"

# A fresh tree: every stand-in records that it ran, and exits with the status named for it.
#   plant <dir> <status of the listed gates> <status of the others>
plant() {
  local dir="$1" listed_status="$2" other_status="$3" name
  rm -rf "$dir"
  mkdir -p "$dir/bench" "$dir/ran"
  cp bench/selfhost_gates.sh "$dir/bench/selfhost_gates.sh"
  for name in $LISTED; do
    printf '#!/bin/sh\ntouch "%s/ran/%s"\nexit %s\n' "$dir" "$name" "$listed_status" > "$dir/bench/$name.sh"
  done
  for name in $OTHERS; do
    printf '#!/bin/sh\ntouch "%s/ran/%s"\nexit %s\n' "$dir" "$name" "$other_status" > "$dir/bench/$name.sh"
  done
}

#   run_as <dir> <system> <machine> [shard]: the runner's status, its output in <dir>/out
run_as() {
  local dir="$1"
  FAKE_SYSTEM="$2" FAKE_MACHINE="$3" SELFHOST_GATE_SHARD="${4:-}" SELFHOST_GATE_LOGS="$dir/logs" \
    PATH="$WORK/bin:$PATH" bash "$dir/bench/selfhost_gates.sh" > "$dir/out" 2>&1
}
ran_count() { ls "$1/ran" | wc -l | tr -d ' '; }

echo "== 1. Darwin arm64 runs every gate, and a failing typed-lowering gate fails the run"
plant "$WORK/t1" 1 0
run_as "$WORK/t1" Darwin arm64 && fail "a failing typed-lowering gate passed on Darwin arm64"
[ "$(ran_count "$WORK/t1")" = "$(( listed_count + 2 ))" ] || fail "Darwin arm64 ran $(ran_count "$WORK/t1") gates, not $(( listed_count + 2 ))"
grep -q 'skipped' "$WORK/t1/out" && fail "Darwin arm64 skipped a gate"

echo "== 2. another host names the typed-lowering gates as skipped and does not run them"
plant "$WORK/t2" 1 0
run_as "$WORK/t2" Linux x86_64 || fail "Linux failed on gates it must skip: $(tail -n 3 "$WORK/t2/out")"
[ "$(ran_count "$WORK/t2")" = "2" ] || fail "Linux ran $(ran_count "$WORK/t2") gates, not the 2 outside the list"
for name in $LISTED; do
  grep -q "^$name  *skipped: needs Darwin arm64, and this host is Linux x86_64\$" "$WORK/t2/out" || fail "$name is not named as skipped on Linux"
done
grep -q "^  2/2 gates exited 0\$" "$WORK/t2/out" || fail "the verdict counts a skipped gate as run: $(grep 'gates exited' "$WORK/t2/out")"
grep -q "^  $listed_count skipped on this host" "$WORK/t2/out" || fail "the verdict does not count the $listed_count skipped gates"
grep -q '^== ALL SELFHOST GATES PASSED$' "$WORK/t2/out" && fail "a run that skipped gates says ALL passed"
plant "$WORK/t2b" 0 1
run_as "$WORK/t2b" Linux x86_64 && fail "a failing gate outside the list passed on Linux"
run_as "$WORK/t2b" Darwin x86_64 && fail "a failing gate outside the list passed on Darwin x86_64"
plant "$WORK/t2c" 1 0
run_as "$WORK/t2c" Darwin x86_64 || fail "Darwin x86_64 ran a typed-lowering gate"

echo "== 3. a listed name with no gate file is refused"
plant "$WORK/t3" 0 0
first=$(echo $LISTED | awk '{print $1}')
rm "$WORK/t3/bench/$first.sh"
run_as "$WORK/t3" Darwin arm64 && fail "a listed gate with no file was accepted"
grep -q "DARWIN_ARM64_GATES names $first" "$WORK/t3/out" || fail "the refusal does not name $first"
[ "$(ran_count "$WORK/t3")" = "0" ] || fail "gates ran after the refusal"

echo "== 4. two shards run every gate exactly once between them"
plant "$WORK/t4" 0 0
run_as "$WORK/t4" Darwin arm64 1/2 || fail "shard 1/2 failed"
one=$(ran_count "$WORK/t4")
ls "$WORK/t4/ran" > "$WORK/shard1"
rm -rf "$WORK/t4/ran"; mkdir "$WORK/t4/ran"
run_as "$WORK/t4" Darwin arm64 2/2 || fail "shard 2/2 failed"
two=$(ran_count "$WORK/t4")
ls "$WORK/t4/ran" > "$WORK/shard2"
[ "$(( one + two ))" = "$(( listed_count + 2 ))" ] || fail "the two shards ran $one and $two gates, not $(( listed_count + 2 )) in all"
[ -z "$(comm -12 "$WORK/shard1" "$WORK/shard2")" ] || fail "a gate ran in both shards"

echo
if [ "$failed" -eq 0 ]; then
  echo "== THE GATE RUNNER HOLDS"
  exit 0
fi
echo "== THE GATE RUNNER DOES NOT HOLD"
exit 1
