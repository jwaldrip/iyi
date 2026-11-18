#!/usr/bin/env bash
# The typed pipeline runs the default optimizer, -O0 disables it, and --release selects the release tier.
# Sample stdout is compared byte for byte; workload stdout is compared the same way after setting aside equally numerous, schema-checked `stats: ` lines.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)" || exit 1
cd "$REPO" || exit 1
. "$REPO/bench/lib/host.sh" || exit 1
require_test_host || exit 1
if [ -z "$PY" ]; then echo 'FAIL: a working Python interpreter is required' >&2; exit 1; fi
. "$REPO/bench/lib/mutation.sh"
REPO_NATIVE="$(native_path "$REPO")" || exit 1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/iyi-opt-pipeline.XXXXXX")" || exit 1
WORK_NATIVE="$(native_path "$WORK")" || exit 1
trap 'rm -rf "$WORK"' EXIT
IYI="$REPO/bin/iyi"
TOOL_SRC="$REPO/src/compiler/tools/compile_native.iyi"
COMPILER_SRC="$REPO/src/compiler/compiler.iyi"
EXECUTE_SRC="$REPO/src/compiler/command/execute.iyi"
FIXTURE="$REPO_NATIVE/bench/fixtures/native_opt_pipeline/tier.iyi"
RELEASE_FIXTURE="$REPO_NATIVE/bench/fixtures/native_opt_pipeline/release.iyi"
PATH_SEP=:
[ "$HOST_OS" = windows ] && PATH_SEP=';'
export IYI_PATH="$REPO_NATIVE/src${PATH_SEP}$REPO_NATIVE/samples/iyi"
mkdir -p "$WORK/bin" "$WORK/ir" "$WORK/default" "$WORK/o0" "$WORK/o3" "$WORK/release" "$WORK/mutant" "$WORK/runs"
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

# Records are path, failing phase, and the first normalized refusal line.
check_ceiling() {
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" "$(native_path "$3")" "$4" <<'PY'
import sys

ceiling, measured, built, lower = sys.argv[1:]
def records(path):
    rows = {}
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            line = line.rstrip('\n')
            if not line or line.startswith('#'):
                continue
            fields = line.split('\t')
            if len(fields) != 3 or not all(fields) or fields[0] in rows:
                raise ValueError('invalid or duplicate ceiling row: ' + line)
            rows[fields[0]] = line
    return rows
try:
    expected, actual = records(ceiling), records(measured)
    with open(built, encoding='utf-8') as stream:
        built_names = set(stream.read().splitlines())
    bad = False
    for name, row in actual.items():
        if name not in expected:
            print('FAIL: unlisted refusal: ' + row)
            bad = True
        elif expected[name] != row:
            print('FAIL: refusal changed: ' + row)
            print('  expected: ' + expected[name])
            bad = True
    for name in expected:
        if name in built_names:
            print('IMPROVED: remove ' + name + ' from the ceiling')
            if lower != '1':
                bad = True
        elif name not in actual:
            print('FAIL: ceiling entry was not measured: ' + name)
            bad = True
    sys.exit(1 if bad else 0)
except (OSError, ValueError) as exc:
    print('FAIL: ' + str(exc))
    sys.exit(1)
PY
}

# Normalize the checkout prefix, preserving the first refusal verbatim otherwise.
refusal_row() {
  local source="$1" stdout="$2" stderr="$3" phase reason
  phase="$(awk '/^\[phase\] [a-z]+: start$/ { p=$2; sub(/:$/, "", p) } END { print p }' "$stdout")"
  reason="$(awk '/^(Error: |iyi: panic: |iyi-compile-native: )/ { print; exit }' "$stderr")"
  [ -n "$phase" ] && [ -n "$reason" ] || return 1
  reason="${reason//"$REPO_NATIVE/"/}"
  reason="${reason//"$REPO/"/}"
  printf '%s\t%s\t%s\n' "$source" "$phase" "$reason"
}

# Compare all non-stat bytes, the number of stat lines and the exact stat schema.
workload_equal() {
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" <<'PY'
import re, sys

def read(path):
    with open(path, 'rb') as stream:
        lines = stream.readlines()
    stats = [line for line in lines if line.startswith(b'stats: ')]
    if any(re.fullmatch(rb'stats: collections=[0-9]+ paused_us=[0-9]+\n', line) is None for line in stats):
        raise ValueError('malformed stats line in ' + path)
    rest = [line for line in lines if not line.startswith(b'stats: ')]
    if sum(line.startswith(b'result=') for line in rest) != 1:
        raise ValueError('expected exactly one result line in ' + path)
    return rest, len(stats)
try:
    a, na = read(sys.argv[1])
    b, nb = read(sys.argv[2])
    if a != b or na != nb:
        print('workload output differs: non-stat lines or stat counts', file=sys.stderr)
        sys.exit(1)
except (OSError, ValueError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
PY
}

# Runtime failures, signals and timeouts are distinguished from ordinary exit statuses.
run_bounded() {
  "$PY" - "$(native_path "$1")" "$(native_path "$2")" "$(native_path "$3")" "$(native_path "$4")" <<'PY'
import os, signal, subprocess, sys
exe, out, err, cwd = sys.argv[1:]
try:
    with open(out, 'wb') as stdout, open(err, 'wb') as stderr:
        process = subprocess.Popen([exe], cwd=cwd, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   start_new_session=(os.name != 'nt'))
        try:
            process.communicate(b'x = 2 + 3 * 4\nx * 10\n', timeout=1800)
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            print('timeout')
        else:
            rc = process.returncode
            print(str(rc) if 0 <= rc <= 255 else 'signal:' + str(-rc) if rc < 0 else 'invalid-exit:' + str(rc))
except OSError as exc:
    print('launch-error:' + str(exc))
PY
}

# Preserve real input and diagnostics when a pass refuses it, even after cleanup.
preserve_ir_failure() {
  local name="$1" pass="${2:-opt}"
  if [ -n "${SELFHOST_GATE_LOGS:-}" ]; then
    mkdir -p "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures"
    cp "$WORK/ir/$name.raw.ir" "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.ir"
    cp "$WORK/ir/$name.$pass.log" "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.log"
    echo "  retained failing IR as $SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.ir"
  fi
}

stop_release_mismatch() {
  local name="$1"
  if [ -n "${SELFHOST_GATE_LOGS:-}" ]; then
    preserve_ir_failure "$name" release
    cp "$WORK/$name.hosted.out" "$WORK/$name.release.out" "$WORK/$name.hosted.err" "$WORK/$name.release.err" \
      "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures/"
  fi
  echo 'SOME NATIVE OPT PIPELINE CHECKS FAILED'
  exit 1
}

echo '== 1. build the native compile tool and optimizer'
if ! "$IYI" build -o "$WORK_NATIVE/bin/compile_native$EXE" "$REPO_NATIVE/src/compiler/tools/compile_native.iyi" >"$WORK/tool.build.log" 2>&1; then
  cat "$WORK/tool.build.log"; echo 'SOME NATIVE OPT PIPELINE CHECKS FAILED'; exit 1
fi
if ! "$IYI" build -o "$WORK_NATIVE/bin/iyi-opt$EXE" "$REPO_NATIVE/src/compiler/tools/ir_opt.iyi" >"$WORK/opt.build.log" 2>&1; then
  cat "$WORK/opt.build.log"; echo 'SOME NATIVE OPT PIPELINE CHECKS FAILED'; exit 1
fi
TOOL="$WORK/bin/compile_native$EXE"
OPT="$WORK/bin/iyi-opt$EXE"

echo '== 2. comparison self-checks and -O0 versus the default IR tier'
printf 'result=7\nstats: collections=2 paused_us=10\n' >"$WORK/comparison.a"
printf 'result=7\nstats: collections=4 paused_us=11\n' >"$WORK/comparison.b"
printf 'result=8\nstats: collections=4 paused_us=11\n' >"$WORK/comparison.wrong"
printf 'result=7\nstats: collections=x paused_us=11\n' >"$WORK/comparison.bad-stats"
if ! workload_equal "$WORK/comparison.a" "$WORK/comparison.b" ||
   workload_equal "$WORK/comparison.a" "$WORK/comparison.wrong" >/dev/null 2>&1 ||
   workload_equal "$WORK/comparison.a" "$WORK/comparison.bad-stats" >/dev/null 2>&1; then
  fail 'workload comparison failed its positive or negative self-check'
else
  echo '  workload comparison catches wrong results and malformed stats'
fi
printf 'samples/iyi/a.iyi\tbodies\tError: fixture refusal\n' >"$WORK/ceiling.test"
cp "$WORK/ceiling.test" "$WORK/measured.test"
: >"$WORK/built.test"
if ! check_ceiling "$WORK/ceiling.test" "$WORK/measured.test" "$WORK/built.test" 0 >/dev/null ||
   { printf 'samples/iyi/b.iyi\tlower\tError: new refusal\n' >>"$WORK/measured.test"
     check_ceiling "$WORK/ceiling.test" "$WORK/measured.test" "$WORK/built.test" 0 >"$WORK/unlisted.test"; } ||
   ! grep -Fq 'FAIL: unlisted refusal:' "$WORK/unlisted.test"; then
  fail 'ceiling failed to catch an unlisted refusal'
else
  echo '  ceiling catches an unlisted refusal'
fi
: >"$WORK/measured.test"
printf 'samples/iyi/a.iyi\n' >"$WORK/built.test"
if check_ceiling "$WORK/ceiling.test" "$WORK/measured.test" "$WORK/built.test" 0 >"$WORK/improved.test" ||
   ! grep -Fxq 'IMPROVED: remove samples/iyi/a.iyi from the ceiling' "$WORK/improved.test" ||
   ! check_ceiling "$WORK/ceiling.test" "$WORK/measured.test" "$WORK/built.test" 1 >/dev/null; then
  fail 'ceiling failed to report a newly buildable sample'
else
  echo '  ceiling reports a newly buildable sample'
fi
if ! "$TOOL" "$FIXTURE" -o "$WORK_NATIVE/o0/tier.ir" --pipeline typed --probe-phase --emit ir -O0 >"$WORK/o0/phase.log" 2>&1 ||
   ! "$TOOL" "$FIXTURE" -o "$WORK_NATIVE/default/tier.ir" --pipeline typed --probe-phase --emit ir >"$WORK/default/phase.log" 2>&1; then
  cat "$WORK/o0/phase.log" "$WORK/default/phase.log" 2>/dev/null
  fail 'tier fixture did not emit IR'
elif ! grep -Fxq '[phase] opt: start' "$WORK/default/phase.log" ||
     ! grep -Fxq '[phase] opt: pass' "$WORK/default/phase.log" ||
     ! grep -Fxq '[phase] opt: pass' "$WORK/o0/phase.log"; then
  fail 'the opt phase is missing from the trace'
elif cmp -s "$WORK/o0/tier.ir" "$WORK/default/tier.ir"; then
  fail 'default and -O0 produced identical IR'
elif ! "$OPT" run --verify-each default "$WORK_NATIVE/o0/tier.ir" >"$WORK/o0/optimized.ir" 2>"$WORK/o0/opt.log" ||
     ! "$OPT" print "$WORK_NATIVE/default/tier.ir" >"$WORK/default/canonical.ir" 2>"$WORK/default/print.log"; then
  cat "$WORK/o0/opt.log" "$WORK/default/print.log" 2>/dev/null
  fail 'the tier fixture failed optimizer verification or canonical printing'
elif ! cmp -s "$WORK/o0/optimized.ir" "$WORK/default/canonical.ir"; then
  fail 'the default compiler IR differs from iyi-opt default applied to -O0 IR'
else
  echo '  -O0 retains unoptimized IR; default equals iyi-opt default'
fi

if ! "$TOOL" "$RELEASE_FIXTURE" -o "$WORK_NATIVE/o0/release.ir" --pipeline typed --emit ir -O0 >"$WORK/o0/release.log" 2>&1 ||
   ! "$TOOL" "$RELEASE_FIXTURE" -o "$WORK_NATIVE/default/release.ir" --pipeline typed --emit ir >"$WORK/default/release.log" 2>&1 ||
   ! "$TOOL" "$RELEASE_FIXTURE" -o "$WORK_NATIVE/release/release.ir" --pipeline typed --probe-phase --emit ir --release >"$WORK/release/phase.log" 2>&1 ||
   ! "$TOOL" "$RELEASE_FIXTURE" -o "$WORK_NATIVE/release/o3.ir" --pipeline typed --emit ir -O3 >"$WORK/release/o3.log" 2>&1; then
  cat "$WORK/o0/release.log" "$WORK/default/release.log" "$WORK/release/phase.log" "$WORK/release/o3.log" 2>/dev/null
  fail 'release tier fixture did not emit IR'
elif ! grep -Fxq '[phase] opt: pass' "$WORK/release/phase.log" ||
     cmp -s "$WORK/default/release.ir" "$WORK/release/release.ir" ||
     ! cmp -s "$WORK/release/release.ir" "$WORK/release/o3.ir"; then
  fail 'release did not change default IR or -O3 differs from --release'
elif ! "$OPT" run --verify-each release "$WORK_NATIVE/o0/release.ir" >"$WORK/o0/release-optimized.ir" 2>"$WORK/o0/release-opt.log" ||
     ! "$OPT" print "$WORK_NATIVE/release/release.ir" >"$WORK/release/canonical.ir" 2>"$WORK/release/print.log"; then
  cat "$WORK/o0/release-opt.log" "$WORK/release/print.log" 2>/dev/null
  fail 'the release fixture failed optimizer verification or canonical printing'
elif ! cmp -s "$WORK/o0/release-optimized.ir" "$WORK/release/canonical.ir"; then
  fail 'compiler release IR differs from iyi-opt release applied to -O0 IR'
else
  echo '  --release differs from default, matches -O3 and equals iyi-opt release'
fi

for flag in -O1 -O2; do
  rm -f "$WORK/refused"
  rc=0
  "$TOOL" "$FIXTURE" -o "$WORK_NATIVE/refused" --pipeline typed "$flag" >"$WORK/refused.out" 2>"$WORK/refused.err" || rc=$?
  expected="-O ${flag#-O} is not in the self-hosted compiler yet"
  if [ "$rc" -ne 1 ] || [ -e "$WORK/refused" ] || ! grep -Fq -- "$expected" "$WORK/refused.err"; then
    fail "compile-native $flag did not refuse by name without output (exit $rc)"
    cat "$WORK/refused.err"
  else
    echo "  compile-native $flag refused without output"
  fi
done

echo '== 3. default command tier and flag refusals'
if [ "$HOST_ID" = darwin-arm64 ]; then
  if ! "$IYI" build -o "$WORK_NATIVE/bin/stage1$EXE" "$REPO_NATIVE/src/compiler/stage1.iyi" >"$WORK/stage1.build.log" 2>&1; then
    cat "$WORK/stage1.build.log"; fail 'the stage-one command did not build'
  else
    STAGE1="$WORK/bin/stage1$EXE"
    if ! "$STAGE1" build --prelude empty -o "$WORK_NATIVE/o0/probe" -O0 "$FIXTURE" >"$WORK/o0/build.log" 2>&1 ||
       ! "$STAGE1" build --prelude empty -o "$WORK_NATIVE/default/probe" "$FIXTURE" >"$WORK/default/build.log" 2>&1; then
      cat "$WORK/o0/build.log" "$WORK/default/build.log" 2>/dev/null
      fail 'the stage-one tier fixture did not build'
    elif cmp -s "$WORK/o0/probe" "$WORK/default/probe"; then
      fail 'default and -O0 stage-one builds are byte-identical'
    else
      o0_status="$(run_bounded "$WORK/o0/probe" "$WORK/o0/run.out" "$WORK/o0/run.err" "$WORK/o0")"
      default_status="$(run_bounded "$WORK/default/probe" "$WORK/default/run.out" "$WORK/default/run.err" "$WORK/default")"
      if [ "$o0_status" != 6 ] || [ "$default_status" != "$o0_status" ] || ! cmp -s "$WORK/o0/run.out" "$WORK/default/run.out"; then
        fail "stage-one tier fixture differs: -O0=$o0_status default=$default_status"
      else
        echo '  stage-one default differs from -O0 and both exit 6'
      fi
    fi
    if ! "$STAGE1" build --prelude empty -o "$WORK_NATIVE/default/release" "$RELEASE_FIXTURE" >"$WORK/default/release-build.log" 2>&1 ||
       ! "$STAGE1" build --prelude empty -o "$WORK_NATIVE/release/release" --release "$RELEASE_FIXTURE" >"$WORK/release/build.log" 2>&1 ||
       ! "$STAGE1" build --prelude empty -o "$WORK_NATIVE/o3/release" -O3 "$RELEASE_FIXTURE" >"$WORK/o3/build.log" 2>&1; then
      cat "$WORK/default/release-build.log" "$WORK/release/build.log" "$WORK/o3/build.log" 2>/dev/null
      fail 'the stage-one release fixture did not build'
    elif cmp -s "$WORK/default/release" "$WORK/release/release" || ! cmp -s "$WORK/o3/release" "$WORK/release/release"; then
      fail 'stage-one release is cosmetic or -O3 differs from --release'
    else
      default_status="$(run_bounded "$WORK/default/release" "$WORK/default/release.out" "$WORK/default/release.err" "$WORK/default")"
      release_status="$(run_bounded "$WORK/release/release" "$WORK/release/run.out" "$WORK/release/run.err" "$WORK/release")"
      o3_status="$(run_bounded "$WORK/o3/release" "$WORK/o3/run.out" "$WORK/o3/run.err" "$WORK/o3")"
      if [ "$default_status" != 3 ] || [ "$release_status" != "$default_status" ] || [ "$o3_status" != "$default_status" ] ||
         ! cmp -s "$WORK/default/release.out" "$WORK/release/run.out" || ! cmp -s "$WORK/default/release.out" "$WORK/o3/run.out"; then
        fail "stage-one release fixture differs: default=$default_status release=$release_status O3=$o3_status"
      else
        echo '  stage-one --release and -O3 differ from default and all exit 3'
      fi
    fi
    for flag in -O1 -O2; do
      rm -f "$WORK/refused"
      rc=0
      "$STAGE1" build --prelude empty -o "$WORK_NATIVE/refused" "$flag" "$FIXTURE" >"$WORK/command-refused.out" 2>"$WORK/command-refused.err" || rc=$?
      expected="-O ${flag#-O} is not in the self-hosted compiler yet"
      if [ "$rc" -ne 1 ] || [ -e "$WORK/refused" ] || ! grep -Fq -- "$expected" "$WORK/command-refused.err"; then
        fail "stage-one $flag did not refuse by name without output (exit $rc)"
        cat "$WORK/command-refused.err"
      else
        echo "  stage-one $flag refused without output"
      fi
    done
  fi
else
  host_limited 'stage-one native builds and command tier checks require darwin-arm64'
fi

echo '== 4. every sample and speed workload: real IR and hosted execution parity'
if [ "$HOST_ID" = darwin-arm64 ]; then
  checked=0
  ceiling="$REPO/bench/native_opt_pipeline.ceiling"
  lower="${NATIVE_OPT_PIPELINE_LOWER:-0}"
  case "$lower" in 0|1) ;; *) fail "invalid NATIVE_OPT_PIPELINE_LOWER=$lower"; lower=0 ;; esac
  : >"$WORK/measured.tsv"
  : >"$WORK/built.txt"
  for source in "$REPO"/samples/iyi/*.iyi "$REPO"/bench/fixtures/native_speed/workloads/*.iyi; do
    [ -f "$source" ] || { fail "source glob did not match: $source"; continue; }
    base="$(basename "$source" .iyi)"
    case "$source" in "$REPO"/samples/iyi/*) kind=sample ;; *) kind=workload ;; esac
    name="$kind-$base"
    rel="${source#"$REPO"/}"
    checked=$((checked + 1))
    source_native="$(native_path "$source")" || { fail "cannot convert path $source"; continue; }
    o0_rc=0
    "$TOOL" "$source_native" -o "$WORK_NATIVE/bin/$name.o0$EXE" --pipeline typed --prelude --probe-phase -O0 >"$WORK/$name.o0.log" 2>"$WORK/$name.o0.err" || o0_rc=$?
    default_rc=0
    "$TOOL" "$source_native" -o "$WORK_NATIVE/bin/$name.native$EXE" --pipeline typed --prelude --probe-phase >"$WORK/$name.native.log" 2>"$WORK/$name.native.err" || default_rc=$?
    release_rc=0
    "$TOOL" "$source_native" -o "$WORK_NATIVE/bin/$name.release$EXE" --pipeline typed --prelude --probe-phase --release >"$WORK/$name.release.log" 2>"$WORK/$name.release.err" || release_rc=$?
    if [ "$o0_rc" -ne 0 ]; then
      if [ "$kind" != sample ] || [ "$o0_rc" -ne 1 ] || [ "$default_rc" -ne 1 ] || [ "$release_rc" -ne 1 ] ||
         [ -e "$WORK/bin/$name.o0$EXE" ] || [ -e "$WORK/bin/$name.native$EXE" ] || [ -e "$WORK/bin/$name.release$EXE" ]; then
        fail "$name: tiers did not all refuse without output (exits $o0_rc/$default_rc/$release_rc)"
        cat "$WORK/$name.o0.log" "$WORK/$name.o0.err" "$WORK/$name.native.log" "$WORK/$name.native.err" "$WORK/$name.release.log" "$WORK/$name.release.err"
        continue
      fi
      o0_row="$(refusal_row "$rel" "$WORK/$name.o0.log" "$WORK/$name.o0.err")" || o0_row=""
      default_row="$(refusal_row "$rel" "$WORK/$name.native.log" "$WORK/$name.native.err")" || default_row=""
      release_row="$(refusal_row "$rel" "$WORK/$name.release.log" "$WORK/$name.release.err")" || release_row=""
      if [ -z "$o0_row" ] || [ "$o0_row" != "$default_row" ] || [ "$o0_row" != "$release_row" ]; then
        fail "$name: tiers refused at different phases or with different reasons"
        cat "$WORK/$name.o0.log" "$WORK/$name.o0.err" "$WORK/$name.native.log" "$WORK/$name.native.err" "$WORK/$name.release.log" "$WORK/$name.release.err"
      else
        printf '%s\n' "$o0_row" >>"$WORK/measured.tsv"
        printf '  refusal: %s\n' "$o0_row"
      fi
      continue
    fi
    if [ "$kind" = sample ]; then printf '%s\n' "$rel" >>"$WORK/built.txt"; fi
    if [ ! -s "$WORK/bin/$name.o0$EXE" ] || [ "$default_rc" -ne 0 ] || [ ! -s "$WORK/bin/$name.native$EXE" ]; then
      fail "$name: -O0 built but the default tier did not (exit $default_rc)"
      cat "$WORK/$name.native.log" "$WORK/$name.native.err"
      continue
    fi
    if [ "$release_rc" -ne 0 ] || [ ! -s "$WORK/bin/$name.release$EXE" ]; then
      fail "$name: -O0 built but release did not (exit $release_rc)"
      cat "$WORK/$name.release.log" "$WORK/$name.release.err"
      if "$TOOL" "$source_native" -o "$WORK_NATIVE/ir/$name.raw.ir" --pipeline typed --prelude --emit ir -O0 >"$WORK/ir/$name.emit.log" 2>&1; then
        cp "$WORK/$name.release.err" "$WORK/ir/$name.release.log"
        preserve_ir_failure "$name" release
      fi
      echo 'SOME NATIVE OPT PIPELINE CHECKS FAILED'
      exit 1
    fi
    if ! "$TOOL" "$source_native" -o "$WORK_NATIVE/ir/$name.raw.ir" --pipeline typed --prelude --emit ir -O0 >"$WORK/ir/$name.emit.log" 2>&1; then
      fail "$name: unoptimized IR emission failed"; cat "$WORK/ir/$name.emit.log"
    elif ! "$OPT" run --verify-each default "$WORK_NATIVE/ir/$name.raw.ir" >"$WORK/ir/$name.optimized.ir" 2>"$WORK/ir/$name.opt.log"; then
      fail "$name: default optimizer refused real IR"; cat "$WORK/ir/$name.opt.log"; preserve_ir_failure "$name"
    else
      echo "  $name: unoptimized IR verified after every default pass"
    fi
    if [ -s "$WORK/ir/$name.raw.ir" ]; then
      if ! "$OPT" run --verify-each release "$WORK_NATIVE/ir/$name.raw.ir" >"$WORK/ir/$name.release.ir" 2>"$WORK/ir/$name.release.log"; then
        fail "$name: release optimizer refused real IR"; cat "$WORK/ir/$name.release.log"; preserve_ir_failure "$name" release
        echo 'SOME NATIVE OPT PIPELINE CHECKS FAILED'
        exit 1
      fi
      echo "  $name: unoptimized IR verified after every release pass"
    fi
    if ! "$IYI" build -o "$WORK_NATIVE/bin/$name.hosted$EXE" "$source_native" >"$WORK/$name.hosted.build.log" 2>&1; then
      fail "$name: hosted build failed"; cat "$WORK/$name.hosted.build.log"; continue
    fi
    mkdir -p "$WORK/runs/$name.hosted" "$WORK/runs/$name.o0" "$WORK/runs/$name.native" "$WORK/runs/$name.release"
    hs="$(run_bounded "$WORK/bin/$name.hosted$EXE" "$WORK/$name.hosted.out" "$WORK/$name.hosted.err" "$WORK/runs/$name.hosted")"
    for tier in o0 native release; do
      previous_failures="$failures"
      ns="$(run_bounded "$WORK/bin/$name.$tier$EXE" "$WORK/$name.$tier.out" "$WORK/$name.$tier.err" "$WORK/runs/$name.$tier")"
      case "$hs:$ns" in
        *[!0-9:]*|:*|*:)
          fail "$name $tier: hosted termination $hs, native termination $ns"
          [ "$tier" != release ] || stop_release_mismatch "$name"
          continue
          ;;
      esac
      if [ "$hs" != "$ns" ]; then
        fail "$name $tier: hosted exit $hs, native exit $ns"
      elif [ "$kind" = sample ] && ! cmp -s "$WORK/$name.hosted.out" "$WORK/$name.$tier.out"; then
        fail "$name $tier: stdout differs"; diff -u "$WORK/$name.hosted.out" "$WORK/$name.$tier.out" || :
      elif [ "$kind" = workload ] && ! workload_equal "$WORK/$name.hosted.out" "$WORK/$name.$tier.out"; then
        fail "$name $tier: stdout differs"; diff -u "$WORK/$name.hosted.out" "$WORK/$name.$tier.out" || :
      else
        echo "  $name $tier: stdout and exit $hs match hosted"
      fi
      if [ "$tier" = release ] && [ "$failures" -gt "$previous_failures" ]; then stop_release_mismatch "$name"; fi
    done
  done
  echo "  checked $checked sample and workload sources"
  if check_ceiling "$ceiling" "$WORK/measured.tsv" "$WORK/built.txt" "$lower"; then
    if [ "$lower" = 1 ]; then
      { grep '^#' "$ceiling"; cat "$WORK/measured.tsv"; } >"$WORK/ceiling.new"
      cp "$WORK/ceiling.new" "$ceiling"
      echo '  refusal ceiling lowered from measured, already listed rows'
    fi
  else
    fail 'refusal ceiling'
  fi
else
  host_limited 'real-program IR, Mach-O builds and execution parity require darwin-arm64'
fi

echo '== 5. mutation proofs'
check_skipped_opt() {
  if [ ! -s "$WORK/default/tier.ir" ] || [ ! -s "$WORK/o0/tier.ir" ]; then echo 'INVALID: tier baseline is missing'; return 2; fi
  if ! "$IYI" build -o "$WORK_NATIVE/mutant/tool$EXE" "$REPO_NATIVE/src/compiler/tools/compile_native.iyi" >"$WORK/mutant/tool.build.log" 2>&1; then
    cat "$WORK/mutant/tool.build.log"; return 2
  fi
  if ! "$WORK/mutant/tool$EXE" "$FIXTURE" -o "$WORK_NATIVE/mutant/tier.ir" --pipeline typed --probe-phase --emit ir >"$WORK/mutant/phase.log" 2>&1; then
    cat "$WORK/mutant/phase.log"; return 2
  fi
  if ! grep -Fxq '[phase] opt: pass' "$WORK/mutant/phase.log" && cmp -s "$WORK/mutant/tier.ir" "$WORK/o0/tier.ir"; then
    echo 'decisive: no opt phase and the unoptimized IR was emitted'; return 1
  fi
  if grep -Fxq '[phase] opt: pass' "$WORK/mutant/phase.log" && cmp -s "$WORK/mutant/tier.ir" "$WORK/default/tier.ir"; then return 0; fi
  echo 'INVALID: mutant neither skipped the phase nor matched the baseline'; return 2
}
if prove_mutation 'the opt phase is skipped' "$COMPILER_SRC" \
'    typed_start("opt")
    options = PassOptions.from_env
    if refusal = run_passes(mod, tier_passes(@config.opt_tier), options)
      return typed_refuse("opt", reached, refusal)
    end
    unless options.verify_each
      opt_errors = verify(mod)
      unless opt_errors.empty?
        return typed_refuse("opt", reached, "the IR verifier refused the module: " + opt_errors[0].to_s)
      end
    end
    reached = typed_pass("opt")' \
'    # opt phase skipped' -- check_skipped_opt; then :; else fail 'skipped-opt mutation'; fi

check_default_none() {
  if [ ! -s "$WORK/o0/probe" ] || [ ! -s "$WORK/default/probe" ]; then echo 'INVALID: command tier baseline is missing'; return 2; fi
  if ! "$IYI" build -o "$WORK_NATIVE/mutant/stage1$EXE" "$REPO_NATIVE/src/compiler/stage1.iyi" >"$WORK/mutant/stage1.build.log" 2>&1; then
    cat "$WORK/mutant/stage1.build.log"; return 2
  fi
  if ! "$WORK/mutant/stage1$EXE" build --prelude empty -o "$WORK_NATIVE/mutant/probe" "$FIXTURE" >"$WORK/mutant/probe.build.log" 2>&1; then
    cat "$WORK/mutant/probe.build.log"; return 2
  fi
  if cmp -s "$WORK/mutant/probe" "$WORK/o0/probe"; then
    echo 'decisive: default command build is identical to -O0'; return 1
  fi
  if cmp -s "$WORK/mutant/probe" "$WORK/default/probe"; then return 0; fi
  echo 'INVALID: mutant command output differs from both baselines'; return 2
}
if [ "$HOST_ID" = darwin-arm64 ]; then
  if prove_mutation 'the command selects None without an -O flag' "$EXECUTE_SRC" \
    '    config.opt_tier = OptTier::None if opts.specified_optimization' \
    '    config.opt_tier = OptTier::None if true' -- check_default_none; then :; else fail 'default-tier mutation'; fi
else
  host_limited 'default command tier mutation requires darwin-arm64'
fi

check_release_skipped() {
  if [ ! -s "$WORK/default/release.ir" ] || [ ! -s "$WORK/release/release.ir" ]; then echo 'INVALID: release IR baseline is missing'; return 2; fi
  if ! "$IYI" build -o "$WORK_NATIVE/mutant/release-tool$EXE" "$REPO_NATIVE/src/compiler/tools/compile_native.iyi" >"$WORK/mutant/release-tool.build.log" 2>&1; then
    cat "$WORK/mutant/release-tool.build.log"; return 2
  fi
  if ! "$WORK/mutant/release-tool$EXE" "$RELEASE_FIXTURE" -o "$WORK_NATIVE/mutant/release.ir" --pipeline typed --emit ir --release >"$WORK/mutant/release-ir.log" 2>&1; then
    cat "$WORK/mutant/release-ir.log"; return 2
  fi
  if cmp -s "$WORK/mutant/release.ir" "$WORK/default/release.ir"; then
    echo 'decisive: release IR used the default pass list'; return 1
  fi
  if cmp -s "$WORK/mutant/release.ir" "$WORK/release/release.ir"; then return 0; fi
  echo 'INVALID: mutant release IR differs from both baselines'; return 2
}
if prove_mutation 'the release tier is skipped' "$COMPILER_SRC" \
  '    if refusal = run_passes(mod, tier_passes(@config.opt_tier), options)' \
  '    if refusal = run_passes(mod, tier_passes(OptTier::Default), options)' -- check_release_skipped; then :; else fail 'release-tier mutation'; fi

check_release_as_default() {
  if [ ! -s "$WORK/default/release" ] || [ ! -s "$WORK/release/release" ]; then echo 'INVALID: release command baseline is missing'; return 2; fi
  if ! "$IYI" build -o "$WORK_NATIVE/mutant/release-stage1$EXE" "$REPO_NATIVE/src/compiler/stage1.iyi" >"$WORK/mutant/release-stage1.build.log" 2>&1; then
    cat "$WORK/mutant/release-stage1.build.log"; return 2
  fi
  if ! "$WORK/mutant/release-stage1$EXE" build --prelude empty -o "$WORK_NATIVE/mutant/release" --release "$RELEASE_FIXTURE" >"$WORK/mutant/release-build.log" 2>&1; then
    cat "$WORK/mutant/release-build.log"; return 2
  fi
  if cmp -s "$WORK/mutant/release" "$WORK/default/release"; then
    echo 'decisive: --release built the default-tier binary'; return 1
  fi
  if cmp -s "$WORK/mutant/release" "$WORK/release/release"; then return 0; fi
  echo 'INVALID: mutant release binary differs from both baselines'; return 2
}
if [ "$HOST_ID" = darwin-arm64 ]; then
  if prove_mutation '--release selects the default tier' "$EXECUTE_SRC" \
    '    config.opt_tier = OptTier::Release if opts.optimization_mode == "3"' \
    '    config.opt_tier = OptTier::Default if opts.optimization_mode == "3"' -- check_release_as_default; then :; else fail 'release command mutation'; fi
else
  host_limited 'release command tier mutation requires darwin-arm64'
fi

echo '== 6. release bootstrap: stage2 equals stage3'
if [ "$HOST_ID" = darwin-arm64 ] && [ -x "$WORK/bin/stage1$EXE" ]; then
  mkdir -p "$WORK/s2" "$WORK/s3"
  if ! IYI_TIME_PASSES=1 /usr/bin/time -l "$STAGE1" build --release -o "$WORK_NATIVE/s2/iyi" "$REPO_NATIVE/src/compiler/stage1.iyi" >"$WORK/s2/build.out" 2>"$WORK/s2/build.log"; then
    fail 'stage1 could not build stage2 in release mode'; cat "$WORK/s2/build.log"
  elif ! IYI_TIME_PASSES=1 /usr/bin/time -l "$WORK/s2/iyi" build --release -o "$WORK_NATIVE/s3/iyi" "$REPO_NATIVE/src/compiler/stage1.iyi" >"$WORK/s3/build.out" 2>"$WORK/s3/build.log"; then
    fail 'stage2 could not build stage3 in release mode'; cat "$WORK/s3/build.log"
  elif ! cmp -s "$WORK/s2/iyi" "$WORK/s3/iyi"; then
    fail 'stage2 and stage3 differ in release mode'
  else
    echo '  release stage2 and stage3 are byte-identical'
  fi
  if [ -n "${SELFHOST_GATE_LOGS:-}" ]; then
    mkdir -p "$SELFHOST_GATE_LOGS"
    cp "$WORK/s2/build.log" "$SELFHOST_GATE_LOGS/native_opt_pipeline_stage2.log"
    [ ! -f "$WORK/s3/build.log" ] || cp "$WORK/s3/build.log" "$SELFHOST_GATE_LOGS/native_opt_pipeline_stage3.log"
  fi
elif [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited 'release bootstrap requires darwin-arm64'
else
  fail 'release bootstrap needs stage1'
fi

if [ "$failures" -eq 0 ]; then
  echo 'ALL NATIVE OPT PIPELINE CHECKS PASSED!'
  exit 0
fi
echo "SOME NATIVE OPT PIPELINE CHECKS FAILED ($failures failures)"
exit 1
