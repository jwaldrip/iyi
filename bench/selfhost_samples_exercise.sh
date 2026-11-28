#!/usr/bin/env bash
# Compare the hosted and stage-one compilers on every top-level sample program.
# samples/iyi/*/*.iyi are imported modules, not the entry programs: they are
# exercised through the samples that import them, rather than run standalone.
#
#   bash bench/selfhost_samples_exercise.sh
#   SAMPLES_RAISE=1 bash bench/selfhost_samples_exercise.sh
#
# A same row must remain same. A refusal becoming same, or changing its first
# diagnostic, needs an explicit floor raise; differences are always failures.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
. "$REPO/bench/lib/host.sh" || exit 1
require_test_host || exit 1
if [ -z "$PY" ]; then
  echo 'a functional Python interpreter is required' >&2
  exit 1
fi
. "$REPO/bench/lib/mutation.sh" || exit 1
REPO_NATIVE="$(native_path "$REPO")" || exit 1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/iyi-samples.XXXXXX")" || exit 1
WORK_NATIVE="$(native_path "$WORK")" || exit 1
trap 'rm -rf "$WORK"' EXIT INT TERM
cd "$REPO" || exit 1

IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
STAGE1="$WORK/stage1$EXE"
STAGE1_NATIVE="$(native_path "$STAGE1")" || exit 1
FLOOR_FILE="$REPO/bench/selfhost_samples.floor"
RAISE="${SAMPLES_RAISE:-0}"
RESULTS="$WORK/results.tsv"
case "$RAISE" in 0|1) ;; *) echo 'SAMPLES_RAISE must be 0 or 1' >&2; exit 1 ;; esac
export IYI_PATH="$REPO_NATIVE/src"
export IYI_CACHE_DIR="$WORK_NATIVE/cache"
export LC_ALL=C
mkdir -p "$WORK/bin" "$WORK/runs"

# This is the same non-release stage-one build as selfhost_stage_one_exercise.
echo '== 1. Building stage one with the hosted compiler'
if ! "$IYI" build -o "$STAGE1_NATIVE" "$REPO_NATIVE/src/compiler/stage1.iyi" > "$WORK/stage1-build.log" 2>&1; then
  cat "$WORK/stage1-build.log"
  echo 'FAIL: stage one did not build'
  exit 1
fi

# The stage-one command currently refuses native builds on every other host.
# Verify that real refusal rather than presenting an unrun corpus as a pass.
if [ "$HOST_ID" != darwin-arm64 ]; then
  rc=0
  "$STAGE1" build -o "$WORK_NATIVE/unsupported$EXE" "$REPO_NATIVE/samples/iyi/hello.iyi" > "$WORK/unsupported.log" 2>&1 || rc=$?
  if [ "$rc" -ne 1 ] || ! grep -Fq 'the native backend builds and runs aarch64-apple-darwin programs, and this host is not one' "$WORK/unsupported.log"; then
    echo 'FAIL: stage one did not report its expected unsupported-host refusal'
    cat "$WORK/unsupported.log"
    exit 1
  fi
  host_limited 'sample build, execution, floors, and mutation proof require the stage-one Darwin arm64 native backend'
  echo '  stage one refused this unsupported host as expected; sample parity was not measured'
  exit 0
fi

# Diagnostics are compared on their first line only. Remove terminal escapes,
# normalize path separators and replace checkout/scratch roots and addresses.
first_diagnostic() {
  "$PY" - "$1" "$REPO_NATIVE" "$WORK_NATIVE" <<'PY'
import os, re, sys
with open(sys.argv[1], 'rb') as f:
    line = f.readline().decode('utf-8', 'replace').rstrip('\r\n')
line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line).replace('\\', '/')
for root in (sys.argv[2], os.path.realpath(sys.argv[2]), sys.argv[3], os.path.realpath(sys.argv[3])):
    root = root.replace('\\', '/').rstrip('/')
    if root:
        line = line.replace(root, '<path>')
line = re.sub(r'0x[0-9a-fA-F]+', '<address>', line)
print(line.replace('\t', ' '))
PY
}

# The hosted reference runs for every built sample, including a stage-one
# refusal. When both build, run them in separate scratch directories.
# A timeout or inability to start is an error, never a matching result.
run_pair() {
  local hosted="$1" stage="$2" label="$3" stage_native=""
  mkdir -p "$WORK/runs/$label-hosted" "$WORK/runs/$label-stage1" || return 1
  [ -z "$stage" ] || stage_native="$(native_path "$stage")" || return 1
  "$PY" - "$(native_path "$hosted")" "$stage_native" \
    "$(native_path "$WORK/runs/$label-hosted")" "$(native_path "$WORK/runs/$label-stage1")" <<'PY'
import subprocess, sys
runs = []
programs = [(sys.argv[1], sys.argv[3])]
if sys.argv[2]:
    programs.append((sys.argv[2], sys.argv[4]))
for exe, cwd in programs:
    try:
        run = subprocess.run([exe], cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print('error\t' + type(exc).__name__ + ': ' + str(exc).replace('\t', ' ').replace('\n', ' '))
        sys.exit(0)
    runs.append((run.returncode, run.stdout, run.stderr))
if len(runs) == 1:
    print('reference\t')
elif runs[0] == runs[1]:
    print('same\t')
else:
    print('different\texit/stdout/stderr differ (hosted exit %s, stage1 exit %s)' % (runs[0][0], runs[1][0]))
PY
}

# Emit one result: path, class, diagnostic, stage-one-build-success (0 or 1).
measure_sample() {
  local stage="$1" sample="$2" tag="$3" hosted built note outcome kind stage_for_run=""
  hosted="$WORK/bin/$tag-hosted$EXE"
  built="$WORK/bin/$tag-stage1$EXE"
  rm -f "$hosted" "$built"
  local hosted_rc=0 stage_rc=0
  "$IYI" build -o "$(native_path "$hosted")" "$sample" > "$WORK/$tag-hosted.build" 2>&1 || hosted_rc=$?
  "$stage" build -o "$(native_path "$built")" "$sample" > "$WORK/$tag-stage1.build" 2>&1 || stage_rc=$?
  if [ "$hosted_rc" -ne 0 ] || [ ! -f "$hosted" ]; then
    note="$(first_diagnostic "$WORK/$tag-hosted.build")"
    printf '%s\terror\thosted build failed (exit %s): %s\t%s\n' "$sample" "$hosted_rc" "$note" "$([ "$stage_rc" -eq 0 ] && [ -f "$built" ] && echo 1 || echo 0)"
    return
  fi
  if [ "$stage_rc" -eq 0 ] && [ -f "$built" ]; then stage_for_run="$built"; fi
  outcome="$(run_pair "$hosted" "$stage_for_run" "$tag")" || outcome=$'error\truntime comparison failed'
  kind="${outcome%%$'\t'*}"
  note="${outcome#*$'\t'}"
  [ "$kind" = "$outcome" ] && note=""
  if [ "$kind" = error ]; then
    printf '%s\terror\t%s\t%s\n' "$sample" "$note" "$([ -n "$stage_for_run" ] && echo 1 || echo 0)"
    return
  fi
  if [ "$stage_rc" -eq 0 ]; then
    if [ -z "$stage_for_run" ]; then
      printf '%s\terror\tstage one exited 0 without an executable\t0\n' "$sample"
      return
    fi
    printf '%s\t%s\t%s\t1\n' "$sample" "$kind" "$note"
  elif [ "$stage_rc" -eq 1 ]; then
    note="$(first_diagnostic "$WORK/$tag-stage1.build")"
    case "$note" in
      'Error: '*|'iyi: panic: '*) printf '%s\trefused\t%s\t0\n' "$sample" "$note" ;;
      *) printf '%s\terror\tstage one exited 1 without a diagnostic: %s\t0\n' "$sample" "$note" ;;
    esac
  else
    note="$(first_diagnostic "$WORK/$tag-stage1.build")"
    printf '%s\terror\tstage one failed unexpectedly (exit %s): %s\t0\n' "$sample" "$stage_rc" "$note"
  fi
}

# The same checker serves the real floor, its temporary controls and the
# source-mutation proof. A raise never permits a regression or a difference.
check_floor() {
  "$PY" - "$1" "$2" "$3" "$4" <<'PY'
import sys
floor_path, results_path, raise_mode, next_path = sys.argv[1:]

def read_floor(path):
    rows = {}
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip('\r\n')
            if not line or line.startswith('#'):
                continue
            fields = line.split('\t')
            if (len(fields) not in (2, 3) or fields[0] in rows or
                fields[1] not in ('same', 'refused') or
                (fields[1] == 'same' and len(fields) != 2) or
                (fields[1] == 'refused' and (len(fields) != 3 or not fields[2]))):
                raise ValueError('invalid or duplicate floor row %s:%s' % (path, number))
            rows[fields[0]] = (fields[1], fields[2] if len(fields) == 3 else '')
    return rows

def read_results(path):
    rows = {}
    with open(path, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            fields = line.rstrip('\r\n').split('\t')
            if len(fields) != 4 or fields[0] in rows or fields[1] not in ('same', 'refused', 'different', 'error') or fields[3] not in ('0', '1'):
                raise ValueError('invalid or duplicate result row %s:%s' % (path, number))
            rows[fields[0]] = (fields[1], fields[2])
    return rows

try:
    floor, results = read_floor(floor_path), read_results(results_path)
except (OSError, ValueError) as exc:
    print('FAIL: ' + str(exc))
    sys.exit(1)
failed = False
if not results:
    print('FAIL: no sample results')
    sys.exit(1)
for sample in sorted(set(floor) - set(results)):
    print('FAIL: floor names a sample not measured: ' + sample)
    failed = True
candidate = dict(floor)
for sample, (actual, note) in sorted(results.items()):
    previous = floor.get(sample)
    if actual in ('different', 'error'):
        print('%s: %s: %s' % (actual.upper(), sample, note))
        failed = True
    elif previous is None:
        print('%s: %s: new sample is %s' % ('raised' if raise_mode == '1' else 'RAISE THE FLOOR', sample, actual))
        candidate[sample] = (actual, note)
        failed |= raise_mode != '1'
    elif previous[0] == 'same' and actual != 'same':
        print('BELOW FLOOR: %s: same -> %s: %s' % (sample, actual, note))
        failed = True
    elif previous[0] == 'refused' and actual == 'same':
        print('%s: %s: refused -> same' % ('raised' if raise_mode == '1' else 'RAISE THE FLOOR', sample))
        candidate[sample] = ('same', '')
        failed |= raise_mode != '1'
    elif actual == 'refused' and previous[1] != note:
        print('%s: %s: %s -> %s' % ('raised' if raise_mode == '1' else 'REFUSAL CHANGED', sample, previous[1], note))
        candidate[sample] = (actual, note)
        failed |= raise_mode != '1'
if failed:
    sys.exit(1)
with open(next_path, 'w', encoding='utf-8', newline='\n') as f:
    f.write('# Stage-one sample floors: path<TAB>same, or path<TAB>refused<TAB>first diagnostic line.\n')
    f.write('# Raise with SAMPLES_RAISE=1 bash bench/selfhost_samples_exercise.sh; a same row never falls.\n')
    for sample, (state, note) in sorted(candidate.items()):
        f.write(sample + '\t' + state + ('\t' + note if state == 'refused' else '') + '\n')
PY
}

echo
echo '== 2. Hosted and stage-one sample results'
: > "$RESULTS"
for sample in samples/iyi/*.iyi; do
  [ -f "$sample" ] || continue
  name="${sample##*/}"
  measure_sample "$STAGE1" "$sample" "${name%.iyi}" >> "$RESULTS"
done
"$PY" - "$RESULTS" <<'PY'
import sys
rows = [line.rstrip('\r\n').split('\t') for line in open(sys.argv[1], encoding='utf-8')]
print('  %-34s %-10s %s' % ('sample', 'class', 'first stage-one diagnostic'))
for sample, state, note, built in rows:
    print('  %-34s %-10s %s' % (sample, state, note))
print('  hosted references completed: %d/%d classified samples' %
      (sum(row[1] in ('same', 'refused', 'different') for row in rows), len(rows)))
print('  totals: %d samples, %d built, %d same, %d refused' %
      (len(rows), sum(row[3] == '1' for row in rows),
       sum(row[1] == 'same' for row in rows), sum(row[1] == 'refused' for row in rows)))
PY

echo
echo '== 3. Checking the floor'
status=0
if ! check_floor "$FLOOR_FILE" "$RESULTS" "$RAISE" "$WORK/floor.new"; then status=1; fi

# Exercise the real floor comparison on temporary floors and measured rows.
echo
echo '== 4. Temporary floor controls'
floor_control() {
  local label="$1" floor_state="$2" floor_note="$3" actual="$4" actual_note="$5" expected="$6" mode="$7"
  if [ "$floor_state" = same ]; then
    printf 'samples/iyi/proof.iyi\tsame\n' > "$WORK/control.floor"
  else
    printf 'samples/iyi/proof.iyi\trefused\t%s\n' "$floor_note" > "$WORK/control.floor"
  fi
  printf 'samples/iyi/proof.iyi\t%s\t%s\t0\n' "$actual" "$actual_note" > "$WORK/control.results"
  if check_floor "$WORK/control.floor" "$WORK/control.results" "$mode" "$WORK/control.new" > "$WORK/control.log" 2>&1; then
    echo "  FAIL: $label was not rejected"
    return 1
  fi
  if ! grep -Fq "$expected" "$WORK/control.log"; then
    echo "  FAIL: $label failed for the wrong reason"
    cat "$WORK/control.log"
    return 1
  fi
  echo "  caught: $label"
  awk 'NR == 1 { print "    " $0; exit }' "$WORK/control.log"
}
floor_control 'same becomes refused, even in raise mode' same '' refused 'Error: refusal' 'BELOW FLOOR:' 1 || status=1
floor_control 'refused becomes same without a raise' refused 'Error: refusal' same '' 'RAISE THE FLOOR:' 0 || status=1
floor_control 'refusal diagnostic changes without a raise' refused 'Error: before' refused 'Error: after' 'REFUSAL CHANGED:' 0 || status=1
floor_control 'different output is never allowed' same '' different 'exit/stdout/stderr differ' 'DIFFERENT:' 1 || status=1

# A raise must actually record either an improvement or a changed refusal.
raise_control() {
  local state="$1" note="$2" expected="$3"
  printf 'samples/iyi/proof.iyi\trefused\tError: before\n' > "$WORK/control.floor"
  printf 'samples/iyi/proof.iyi\t%s\t%s\t0\n' "$state" "$note" > "$WORK/control.results"
  if ! check_floor "$WORK/control.floor" "$WORK/control.results" 1 "$WORK/control.new" > "$WORK/control.log" 2>&1 ||
     ! grep -Fxq "$expected" "$WORK/control.new"; then
    echo "  FAIL: raise mode did not record $state"
    cat "$WORK/control.log"
    return 1
  fi
  echo "  passed: raise mode records $state"
}
raise_control same '' $'samples/iyi/proof.iyi\tsame' || status=1
raise_control refused 'Error: after' $'samples/iyi/proof.iyi\trefused\tError: after' || status=1

# Mutate a scratch copy of the entry point, not the checkout. The mutant must
# compile, refuse hello in the intended way, and be rejected by the real floor.
echo
echo '== 5. Stage-one source mutation'
mkdir -p "$WORK/mutant/src/compiler"
cp "$REPO/src/compiler/stage1.iyi" "$WORK/mutant/src/compiler/stage1.iyi"
mutation_regresses() {
  local mutant="$WORK/mutant-stage1$EXE" line
  if ! "$IYI" build -o "$(native_path "$mutant")" "$(native_path "$WORK/mutant/src/compiler/stage1.iyi")" > "$WORK/mutant-build.log" 2>&1; then
    echo 'mutant did not compile; this proves nothing'
    cat "$WORK/mutant-build.log"
    return 2
  fi
  line="$(measure_sample "$mutant" samples/iyi/hello.iyi mutant-hello)"
  case "$line" in
    $'samples/iyi/hello.iyi\trefused\tError: sample gate mutation\t0') ;;
    *) echo "mutant did not produce the intended refusal: $line"; return 2 ;;
  esac
  awk -F '\t' '$1 != "samples/iyi/hello.iyi"' "$RESULTS" > "$WORK/mutant.results"
  printf '%s\n' "$line" >> "$WORK/mutant.results"
  if check_floor "$FLOOR_FILE" "$WORK/mutant.results" 0 "$WORK/mutant.floor" > "$WORK/mutant-check.log" 2>&1; then
    echo 'mutant passed the real floor'
    return 0
  fi
  if grep -Fq 'BELOW FLOOR: samples/iyi/hello.iyi: same -> refused: Error: sample gate mutation' "$WORK/mutant-check.log"; then
    echo 'decisive: same hello sample refused by mutated stage one, rejected by the real floor'
    return 1
  fi
  cat "$WORK/mutant-check.log"
  return 2
}
if ! prove_mutation 'stage-one refusal of a same sample' "$WORK/mutant/src/compiler/stage1.iyi" \
  '  LibC.exit(CommandExecutor.execute(result, {{ env("IYI_CONFIG_PATH") }}))' \
  $'  STDERR.puts "Error: sample gate mutation"\n  LibC.exit(1)' -- mutation_regresses; then
  status=1
fi

if [ "$status" -eq 0 ] && [ "$RAISE" = 1 ]; then
  cp "$WORK/floor.new" "$FLOOR_FILE"
  echo '  wrote raised sample floor'
fi
echo
if [ "$status" -eq 0 ]; then
  echo 'ALL SELFHOST SAMPLE CHECKS PASSED'
else
  echo 'SELFHOST SAMPLE CHECKS FAILED'
fi
exit "$status"
