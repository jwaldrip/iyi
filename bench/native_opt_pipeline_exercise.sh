#!/usr/bin/env bash
# The typed pipeline runs the default optimizer unless -O0 is requested.
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
PATH_SEP=:
[ "$HOST_OS" = windows ] && PATH_SEP=';'
export IYI_PATH="$REPO_NATIVE/src${PATH_SEP}$REPO_NATIVE/samples/iyi"
mkdir -p "$WORK/bin" "$WORK/ir" "$WORK/default" "$WORK/o0" "$WORK/mutant" "$WORK/runs"
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

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
  local name="$1"
  if [ -n "${SELFHOST_GATE_LOGS:-}" ]; then
    mkdir -p "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures"
    cp "$WORK/ir/$name.raw.ir" "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.ir"
    cp "$WORK/ir/$name.opt.log" "$SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.log"
    echo "  retained failing IR as $SELFHOST_GATE_LOGS/native_opt_pipeline_failures/$name.ir"
  fi
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

for flag in -O1 -O2 -O3 --release; do
  rm -f "$WORK/refused"
  rc=0
  "$TOOL" "$FIXTURE" -o "$WORK_NATIVE/refused" --pipeline typed "$flag" >"$WORK/refused.out" 2>"$WORK/refused.err" || rc=$?
  case "$flag" in
    --release) expected='--release is not in the self-hosted compiler yet' ;;
    *) expected="-O ${flag#-O} is not in the self-hosted compiler yet" ;;
  esac
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
    for flag in -O1 -O2 -O3 --release; do
      rm -f "$WORK/refused"
      rc=0
      "$STAGE1" build --prelude empty -o "$WORK_NATIVE/refused" "$flag" "$FIXTURE" >"$WORK/command-refused.out" 2>"$WORK/command-refused.err" || rc=$?
      case "$flag" in
        --release) expected='--release is not in the self-hosted compiler yet' ;;
        *) expected="-O ${flag#-O} is not in the self-hosted compiler yet" ;;
      esac
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
  for source in "$REPO"/samples/iyi/*.iyi "$REPO"/bench/fixtures/native_speed/workloads/*.iyi; do
    [ -f "$source" ] || { fail "source glob did not match: $source"; continue; }
    base="$(basename "$source" .iyi)"
    case "$source" in "$REPO"/samples/iyi/*) kind=sample ;; *) kind=workload ;; esac
    name="$kind-$base"
    checked=$((checked + 1))
    source_native="$(native_path "$source")" || { fail "cannot convert path $source"; continue; }
    if ! "$TOOL" "$source_native" -o "$WORK_NATIVE/ir/$name.raw.ir" --pipeline typed --prelude --emit ir -O0 >"$WORK/ir/$name.emit.log" 2>&1; then
      fail "$name: unoptimized IR emission failed"; cat "$WORK/ir/$name.emit.log"
    elif ! "$OPT" run --verify-each default "$WORK_NATIVE/ir/$name.raw.ir" >"$WORK/ir/$name.optimized.ir" 2>"$WORK/ir/$name.opt.log"; then
      fail "$name: default optimizer refused real IR"; cat "$WORK/ir/$name.opt.log"; preserve_ir_failure "$name"
    else
      echo "  $name: unoptimized IR verified after every default pass"
    fi
    if ! "$IYI" build -o "$WORK_NATIVE/bin/$name.hosted$EXE" "$source_native" >"$WORK/$name.hosted.build.log" 2>&1; then
      fail "$name: hosted build failed"; cat "$WORK/$name.hosted.build.log"; continue
    fi
    if ! "$TOOL" "$source_native" -o "$WORK_NATIVE/bin/$name.native$EXE" --pipeline typed --prelude >"$WORK/$name.native.build.log" 2>&1; then
      fail "$name: native default build failed"; cat "$WORK/$name.native.build.log"; continue
    fi
    mkdir -p "$WORK/runs/$name.hosted" "$WORK/runs/$name.native"
    hs="$(run_bounded "$WORK/bin/$name.hosted$EXE" "$WORK/$name.hosted.out" "$WORK/$name.hosted.err" "$WORK/runs/$name.hosted")"
    ns="$(run_bounded "$WORK/bin/$name.native$EXE" "$WORK/$name.native.out" "$WORK/$name.native.err" "$WORK/runs/$name.native")"
    case "$hs:$ns" in *[!0-9:]*) fail "$name: hosted termination $hs, native termination $ns"; continue ;; esac
    if [ "$hs" != "$ns" ]; then
      fail "$name: hosted exit $hs, native exit $ns"
    elif [ "$kind" = sample ] && ! cmp -s "$WORK/$name.hosted.out" "$WORK/$name.native.out"; then
      fail "$name: stdout differs"; diff -u "$WORK/$name.hosted.out" "$WORK/$name.native.out" || :
    elif [ "$kind" = workload ] && ! workload_equal "$WORK/$name.hosted.out" "$WORK/$name.native.out"; then
      fail "$name: stdout differs"; diff -u "$WORK/$name.hosted.out" "$WORK/$name.native.out" || :
    else
      echo "  $name: stdout and exit $hs match hosted"
    fi
  done
  echo "  checked $checked sample and workload sources"
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

if [ "$failures" -eq 0 ]; then
  echo 'ALL NATIVE OPT PIPELINE CHECKS PASSED!'
  exit 0
fi
echo "SOME NATIVE OPT PIPELINE CHECKS FAILED ($failures failures)"
exit 1
