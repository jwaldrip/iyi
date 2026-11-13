#!/usr/bin/env bash
# The mutation runner's own exercise (bench/lib/mutation.sh). Every self-host gate proves
# its checks with that runner, so the runner is proved here, on a scratch file.
#
#   bash bench/mutation_runner_exercise.sh
#
# 1. A check that fails on the patched file is caught, and the file is restored.
# 2. A check that passes on the patched file is reported as not caught, and the file is restored.
# 3. A patch that changes nothing is refused with status 3.
# 4. Every process the check starts is in the check's own process group: a command of a
#    pipeline inside the check has the check's shell as its group leader.
# 5. An interrupt (TERM) while the check runs restores the file and stops what the check started.
# 6. Job control is on for the check alone: the runner's own commands around it run in the
#    caller's process group. (With it on for them too, each got a group of its own, and a
#    lost race for one printed `child setpgid ... Operation not permitted` beside a proof.)
# 7. The backup and the restore are the file's contents, written and compared: no `cp` is run.
#    (On an overlay checkout darwin's cp exits 1 after copying every byte, for the extended
#    attributes it cannot read, and its complaint sat beside each proof.)
# 8. A file that cannot be restored stops the run with status 2, and what it held is kept.
set -u
cd "$(dirname "$0")/.." || exit 1
REPO=$PWD

# No trap is set here: the runner is called in subshells below, and in a subshell bash
# reports its parent's traps, which the runner would then put back there. The scratch
# directory is removed at the end instead.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/mutation-runner.XXXXXX")
failed=0
fail() { echo "FAIL: $*"; failed=1; }

fresh() { printf 'alpha\nbeta\n' > "$WORK/target"; }
# Fails when the target no longer holds its first line.
holds_alpha() { grep -q '^alpha$' "$WORK/target"; }
# Passes whatever the target holds.
always_passes() { return 0; }

echo "== 1. a failing check is caught, and the file is restored"
fresh
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- holds_alpha ) ; rc=$?
[ "$rc" -eq 0 ] || fail "a caught mutation answered $rc"
echo "$out" | grep -q 'caught: alpha becomes gamma' || fail "the caught line is missing: $out"
holds_alpha || fail "the file was not restored after a caught mutation"

echo "== 2. a passing check is not caught, and the file is restored"
fresh
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "nobody looks" "$WORK/target" alpha gamma -- always_passes ) ; rc=$?
[ "$rc" -eq 1 ] || fail "an uncaught mutation answered $rc"
echo "$out" | grep -q 'FAIL: mutation was not caught: nobody looks' || fail "the not-caught line is missing: $out"
holds_alpha || fail "the file was not restored after an uncaught mutation"

echo "== 3. a patch that changes nothing is refused"
fresh
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "no such text" "$WORK/target" delta gamma -- holds_alpha ) ; rc=$?
[ "$rc" -eq 3 ] || fail "a patch whose text is absent answered $rc, not 3"
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "same text" "$WORK/target" alpha alpha -- holds_alpha ) ; rc=$?
[ "$rc" -eq 3 ] || fail "a patch that replaces text with itself answered $rc, not 3"

echo "== 4. what the check starts stays in the check's process group"
fresh
# The check's own shell is the parent of the commands it starts and the leader of the job's
# group. A command of a pipeline writes down its parent and its group: they must be one pid.
records_group() {
  true | sh -c 'echo "$PPID $(perl -e "print getpgrp(0)")"' > "$WORK/group"
  holds_alpha
}
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- records_group ) ; rc=$?
[ "$rc" -eq 0 ] || fail "the group check's mutation answered $rc: $out"
read -r parent group < "$WORK/group" || fail "the check wrote no group record"
[ -n "${parent:-}" ] && [ "${parent:-}" = "${group:-}" ] || fail "a pipeline inside the check ran in group ${group:-?}, not the check's own ${parent:-?}"

echo "== 5. TERM during the check restores the file and stops the check's processes"
fresh
slow_check() {
  sh -c 'echo $$ > "$1"; exec sleep 600' sh "$WORK/sleeper" | cat
  holds_alpha
}
(
  . "$REPO/bench/lib/mutation.sh"
  prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- slow_check
) > "$WORK/term.out" 2>&1 &
runner=$!
tries=0
while [ ! -s "$WORK/sleeper" ] && [ "$tries" -lt 100 ]; do sleep 0.1; tries=$(( tries + 1 )); done
[ -s "$WORK/sleeper" ] || fail "the slow check never started"
grep -q '^gamma$' "$WORK/target" || fail "the file was not patched while the check ran"
kill -TERM "$runner" 2>/dev/null
wait "$runner" 2>/dev/null
holds_alpha || fail "TERM left the mutated file behind"
sleeper=$(cat "$WORK/sleeper" 2>/dev/null)
tries=0
while [ -n "$sleeper" ] && kill -0 "$sleeper" 2>/dev/null && [ "$tries" -lt 50 ]; do sleep 0.1; tries=$(( tries + 1 )); done
if [ -n "$sleeper" ] && kill -0 "$sleeper" 2>/dev/null; then
  kill -KILL "$sleeper" 2>/dev/null
  fail "TERM left a process of the check running"
fi

echo "== 6. the runner's own commands stay in the caller's process group"
fresh
mkdir -p "$WORK/bin"
# An `rm` that writes down the process group it runs in, then removes as asked. The group is
# read with perl, which the runner already needs; a container may have no `ps`.
printf '#!/bin/sh\nperl -e "print getpgrp(0), qq(\\n)" >> "$RM_GROUPS"\nexec /bin/rm "$@"\n' > "$WORK/bin/rm"
chmod +x "$WORK/bin/rm"
own_group=$(perl -e 'print getpgrp(0)')
out=$( . "$REPO/bench/lib/mutation.sh"; export RM_GROUPS="$WORK/rm_groups"; PATH="$WORK/bin:$PATH"; prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- holds_alpha ) ; rc=$?
[ "$rc" -eq 0 ] || fail "the mutation of step 6 answered $rc: $out"
[ -s "$WORK/rm_groups" ] || fail "the runner removed nothing through the recording rm"
strays=$(awk -v own="$own_group" '$1 != own' "$WORK/rm_groups" 2>/dev/null | wc -l | tr -d ' ')
[ "$strays" = "0" ] || fail "$strays of the runner's own commands ran in a process group of their own"

echo "== 7. the backup and the restore are the file's contents, compared: no cp is run"
fresh
# A `cp` that only complains: the runner must never reach it.
printf '#!/bin/sh\necho "cp was called: $*" >&2\nexit 1\n' > "$WORK/bin/cp"
chmod +x "$WORK/bin/cp"
out=$( . "$REPO/bench/lib/mutation.sh"; export RM_GROUPS="$WORK/rm_groups_7"; PATH="$WORK/bin:$PATH"; prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- holds_alpha 2>&1 ) ; rc=$?
[ "$rc" -eq 0 ] || fail "the mutation of step 7 answered $rc: $out"
if echo "$out" | grep -q 'cp was called'; then fail "the runner ran cp: $out"; fi
holds_alpha || fail "the file was not restored without cp"

echo "== 8. a file that cannot be restored stops the run, and what it held is kept"
fresh
# The check puts a directory where the file was, so nothing can be written back (true for root too).
blocks_restore() { /bin/rm -f "$WORK/target"; mkdir "$WORK/target"; return 1; }
out=$( . "$REPO/bench/lib/mutation.sh"; prove_mutation "alpha becomes gamma" "$WORK/target" alpha gamma -- blocks_restore 2>&1 ) ; rc=$?
[ "$rc" -eq 2 ] || fail "a restore that could not be made answered $rc, not 2: $out"
echo "$out" | grep -q 'WAS NOT RESTORED' || fail "the runner did not say the file was not restored: $out"
kept=$(echo "$out" | sed -n 's/.*before the mutation is in \(.*\)$/\1/p' | head -n 1)
if [ -n "$kept" ] && grep -q '^alpha$' "$kept" 2>/dev/null; then
  /bin/rm -f "$kept"
else
  fail "what the file held was not kept: $out"
fi
rmdir "$WORK/target" 2>/dev/null

rm -rf "$WORK"
echo
if [ "$failed" -eq 0 ]; then
  echo "== THE MUTATION RUNNER HOLDS"
  exit 0
fi
echo "== THE MUTATION RUNNER DOES NOT HOLD"
exit 1
