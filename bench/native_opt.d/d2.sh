# D2: a switch whose arms only select constants becomes a value (switch-value). Changed and refused fixtures, the release
# order, the runtime twins, the scale bound, and one mutation proof per rule and per refusal that changes output.
echo '== D2. switch values'
for name in d2_affine d2_table d2_holes d2_default_join d2_high d2_i1_affine d2_value_wrap d2_direct_join \
            d2_external_pred d2_dispatch d2_two_phis d2_i1_table; do
  fixture_check switch-value "$name" changed
done
fixture_check switch-chain,switch-value d2_duplicate changed switch-value
for name in d2_three d2_span d2_sign_wrap d2_duplicate_switch d2_arm_inst d2_nonconstant d2_wide d2_float \
            d2_null d2_address d2_undef d2_no_phi d2_holes_nonvalue d2_holes_nonconstant d2_sparse \
            d2_many_phis d2_arm_pred d2_split_join d2_self_join; do
  fixture_check switch-value "$name" keep
done
fixture_stats switch-value "$FIXTURES/switch-value/d2_affine.ir"
fixture_stats switch-value "$FIXTURES/switch-value/d2_table.ir"

# A table is made only for a function that survives DeadFn, which the release tier runs before SwitchValue. The golden
# is the proof. The second run is compared for determinism only: the release tier does not clean up after SwitchValue,
# so a join left with one predecessor stays, as SwitchChain's output does.
if "$DRV" run --verify-each release "$FIXTURES/switch-value/d2_dead.ir" >"$WORK/d2-dead.ir" &&
   "$DRV" run --verify-each release "$FIXTURES/switch-value/d2_dead.ir" >"$WORK/d2-dead-again.ir" &&
   cmp -s "$WORK/d2-dead.ir" "$WORK/d2-dead-again.ir" &&
   cmp -s "$WORK/d2-dead.ir" "$FIXTURES/switch-value/d2_dead.out.ir" &&
   grep -q '^@__iyi_switch_value.live.0 ' "$WORK/d2-dead.ir" &&
   ! grep -q 'switch_value.dead' "$WORK/d2-dead.ir"; then
  echo '  ok: D2 release tier: a deleted function leaves no table, the live function keeps its table'
else
  fail 'D2 release tier: dead-function table'
  head -n 40 "$WORK/d2-dead.ir" 2>/dev/null
fi

# Scale (decision of 2026-11-26): the least CPU of five runs with 500 and 1000 switches, each of four arms, all feeding
# one join, must be within 2.5 times. A switch's span is at most 256, so the pass's cost grows with the number of
# switches and with the join's predecessors. Portable: no /usr/bin/time.
d2_scale_check() {
  local binary="$1"
  "$PY" - "$binary" "$WORK" <<'PY'
import os
import subprocess
import sys

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    get_times = ctypes.windll.kernel32.GetProcessTimes
    get_times.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    get_times.restype = wintypes.BOOL
else:
    import resource

binary, work = sys.argv[1:]
header = '''; iyi-ir 1
source_filename = "d2_scale"
target triple = "aarch64-apple-darwin"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
'''

def make(heads):
    path = os.path.join(work, 'd2-scale-%d.ir' % heads)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('define external i32 @dispatch(i32 %x) {\nentry:\n  br label %h0\n')
        for h in range(heads):
            following = 'h%d' % (h + 1) if h + 1 < heads else 'otherwise'
            f.write('h%d:\n  switch i32 %%x, label %%%s [ i32 0, label %%a%d_0, i32 1, label %%a%d_1, '
                    'i32 2, label %%a%d_2, i32 3, label %%a%d_3 ]\n' % (h, following, h, h, h, h))
        for h in range(heads):
            for k in range(4):
                f.write('a%d_%d:\n  br label %%join\n' % (h, k))
        f.write('otherwise:\n  unreachable\njoin:\n')
        f.write('  %%v = phi i32 %s\n' % ', '.join('[ %d, label %%a%d_%d ]' % (2 * k + 1, h, k)
                                                  for h in range(heads) for k in range(4)))
        f.write('  ret i32 %v\n}\n')
    return path

paths = {n: make(n) for n in (500, 1000)}
times = {500: [], 1000: []}
env = dict(os.environ, GC_MARKERS='1', GC_NPROCS='1')

def cpu_seconds(path):
    if os.name != 'nt':
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
    proc = subprocess.Popen([binary, 'run', '--no-verify', 'switch-value', path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        out, err = proc.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        raise
    if os.name == 'nt':
        created, exited, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not get_times(int(proc._handle), ctypes.byref(created), ctypes.byref(exited),
                         ctypes.byref(kernel), ctypes.byref(user)):
            raise OSError('GetProcessTimes failed')
        def seconds(t):
            return ((t.dwHighDateTime << 32) | t.dwLowDateTime) / 10000000.0
        elapsed = seconds(kernel) + seconds(user)
    else:
        after = resource.getrusage(resource.RUSAGE_CHILDREN)
        elapsed = (after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)
    if proc.returncode != 0:
        raise RuntimeError('scale optimizer failed: ' + err.decode('utf-8', 'replace'))
    if b'switch.affine.in_range' not in out or b'switch i32 %x' in out:
        raise RuntimeError('scale switches were not converted')
    return elapsed

try:
    for _ in range(5):
        for n in (500, 1000):
            times[n].append(cpu_seconds(paths[n]))
    small = min(times[500])
    large = min(times[1000])
    if small <= 0:
        raise RuntimeError('scale timer returned zero')
    ratio = large / small
    print('  d2 scale: 500 switches=%.6fs 1000 switches=%.6fs ratio=%.3f (least of 5 CPU runs)' % (small, large, ratio))
    if ratio > 2.5:
        print('decisive: D2 scale ratio %.3f exceeds 2.5' % ratio)
        sys.exit(1)
except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
    print('FAIL: D2 scale:', exc, file=sys.stderr)
    sys.exit(2)
PY
}

d2_scale_mutation() {
  if ! build_driver "$MUTANT"; then
    echo "D2 scale mutant did not build" >&2
    cat "$WORK/build.log" >&2
    return 2
  fi
  d2_scale_check "$MUTANT"
}

if d2_scale_check "$DRV"; then
  prove_mutation 'D2: the join is indexed once, not for every case' src/compiler/ir/opt/switch_value.iyi \
    '    inputs = @inputs[phi]?' \
    '    inputs = nil # mutation: every case indexes the join again' \
    -- d2_scale_mutation || fail 'D2 scale mutation was not caught'
else
  fail 'D2 scale contract failed'
fi

# Mutation proofs. Each patch changes one rule or refusal; the named fixture must then differ from its golden.
prove_mutation 'D2: the affine fit accepts a case that does not fit' src/compiler/ir/opt/switch_value.iyi \
  '      if canonical(bits, (@slope &* k.to_i64) &+ @intercept) != @entries[k] # mutation D2-affine-fit' \
  '      if false # mutation: the affine fit accepts every case' \
  -- mutation_check D2AffineFit switch-value d2_table || fail 'D2 affine-fit mutation was not caught'
mutation_result D2AffineFit

prove_mutation 'D2: the range check is not off by one' src/compiler/ir/opt/switch_value.iyi \
  '    in_range = builder.icmp(IntPredicate::ULE, index, builder.const_int(selector.type, span - 1), "switch.#{kind}.in_range") # mutation D2-range' \
  '    in_range = builder.icmp(IntPredicate::ULE, index, builder.const_int(selector.type, span), "switch.#{kind}.in_range") # mutation: the range check is off by one' \
  -- mutation_check D2Range switch-value d2_affine || fail 'D2 range mutation was not caught'
mutation_result D2Range

prove_mutation 'D2: a hole takes its neighbour, not the default value' src/compiler/ir/opt/switch_value.iyi \
  '      plan = PhiPlan.new(phi, entries)' \
  '      k = 1
      while k < span
        entries[k] = entries[k - 1] if entries[k] == fill # mutation: a hole takes its neighbour
        k = k + 1
      end
      plan = PhiPlan.new(phi, entries)' \
  -- mutation_check D2HoleFill switch-value d2_holes || fail 'D2 hole-fill mutation was not caught'
mutation_result D2HoleFill

prove_mutation 'D2: the table is indexed by the key minus the lowest case' src/compiler/ir/opt/switch_value.iyi \
  '      pointer_index = cast_index(builder, index, pointer_type, cache) # mutation D2-table-index' \
  '      pointer_index = cast_index(builder, stable, pointer_type, cache) # mutation: the table is indexed by the key' \
  -- mutation_check D2TableIndex switch-value d2_table || fail 'D2 table-index mutation was not caught'
mutation_result D2TableIndex

prove_mutation 'D2: a duplicate key within one switch is refused' src/compiler/ir/opt/switch_value.iyi \
  '      return false if seen.has_key?(key) # mutation D2-duplicate' \
  '      return false if false # mutation: a duplicate key is not refused' \
  -- mutation_check D2Duplicate switch-value d2_duplicate_switch || fail 'D2 duplicate mutation was not caught'
mutation_result D2Duplicate

prove_mutation 'D2: a span of more than 256 keys is refused' src/compiler/ir/opt/switch_value.iyi \
  '    return false if high - low >= MAX_SPAN.to_u64 # mutation D2-span' \
  '    return false if high - low >= 1024_u64 # mutation: spans up to 1024' \
  -- mutation_check D2Span switch-value d2_span || fail 'D2 span mutation was not caught'
mutation_result D2Span

prove_mutation 'D2: an arm holding an instruction is refused' src/compiler/ir/opt/switch_value.iyi \
  '        return false unless branch_only?(target) # mutation D2-arm-instructions' \
  '        return false if false # mutation: an arm may hold instructions' \
  -- mutation_check D2ArmInstructions switch-value d2_arm_inst || fail 'D2 arm-instruction mutation was not caught'
mutation_result D2ArmInstructions

prove_mutation 'D2: an arm with another predecessor is refused' src/compiler/ir/opt/switch_value.iyi \
  '        return false unless target.preds.size == 1 && target.preds[0] == head # mutation D2-predecessor' \
  '        return false if false # mutation: an arm may have other predecessors' \
  -- mutation_check D2Predecessor switch-value d2_arm_pred || fail 'D2 predecessor mutation was not caught'
mutation_result D2Predecessor

prove_mutation 'D2: a join that is the switch head itself is refused' src/compiler/ir/opt/switch_value.iyi \
  '    return false if join == head' \
  '    return false if false # mutation: a self join is converted' \
  -- mutation_check D2SelfJoin switch-value d2_self_join || fail 'D2 self-join mutation was not caught'
mutation_result D2SelfJoin

prove_mutation 'D2: a join with no phi is refused' src/compiler/ir/opt/switch_value.iyi \
  '    return false if plans.empty? # mutation D2-no-phi' \
  '    return false if false # mutation: a join with no phi is converted' \
  -- mutation_check D2NoPhi switch-value d2_no_phi || fail 'D2 no-phi mutation was not caught'
mutation_result D2NoPhi

prove_mutation 'D2: at most four tables per switch' src/compiler/ir/opt/switch_value.iyi \
  '    return false if tables > MAX_TABLES # mutation D2-table-count' \
  '    return false if tables > 99 # mutation: any number of tables' \
  -- mutation_check D2TableCount switch-value d2_many_phis || fail 'D2 table-count mutation was not caught'
mutation_result D2TableCount

prove_mutation 'D2: a table needs cases on at least 40 percent of its span' src/compiler/ir/opt/switch_value.iyi \
  '    return false if tables > 0 && keys.size * 5 < span * 2 # mutation D2-table-density' \
  '    return false if tables > 0 && false # mutation: sparse tables are allowed' \
  -- mutation_check D2TableDensity switch-value d2_sparse || fail 'D2 table-density mutation was not caught'
mutation_result D2TableDensity

prove_mutation 'D2: the release tier runs SwitchValue before DeadFn' src/compiler/ir/opt/pipeline.iyi \
  '            PassId::SwitchChain, PassId::DeadFn, PassId::SwitchValue, PassId::Layout]' \
  '            PassId::SwitchChain, PassId::SwitchValue, PassId::DeadFn, PassId::Layout]' \
  -- mutation_check D2Order release d2_dead switch-value || fail 'D2 release-order mutation was not caught'
mutation_result D2Order

# Runtime twins. d2_runtime_wasm.ir reads its selectors from memory and is run through switch-value alone, so no inliner
# folds them. The optimized module must print what the unoptimized module prints, as an aarch64 program and as a
# wasm32-wasi module. The aarch64 run needs macOS arm64; the wasm run needs wasmtime.
echo '== D2. runtime twins'
RT="$FIXTURES/switch-value/d2_runtime_wasm.ir"
WASMTIME_D2=${WASMTIME:-$(command -v wasmtime 2>/dev/null || true)}
if [ -z "$WASMTIME_D2" ] && [ -x "$HOME/.wasmtime/bin/wasmtime$EXE" ]; then
  WASMTIME_D2="$HOME/.wasmtime/bin/wasmtime$EXE"
fi
if [ "$HOST_ID" != darwin-arm64 ]; then
  host_limited 'D2 runtime twins run the aarch64 program on macOS arm64 only'
elif ! ./bin/iyi build -o "$(native_path "$WORK/d2-cn$EXE")" src/compiler/tools/compile_native.iyi >"$WORK/d2-cn.log" 2>&1; then
  cat "$WORK/d2-cn.log"
  fail 'D2 runtime: the native compiler does not build'
else
  CN="$WORK/d2-cn$EXE"
  if ! "$DRV" run --verify-each switch-value "$RT" >"$WORK/d2-rt-opt.ir" 2>"$WORK/d2-rt-opt.err"; then
    cat "$WORK/d2-rt-opt.err"
    fail 'D2 runtime: switch-value did not run on the twin'
  fi
  "$PY" "$REPO/bench/native_wasm_darwin.py" "$RT" "$WORK/d2-rt-plain-darwin.ir" || fail 'D2 runtime: aarch64 conversion of the plain module'
  "$PY" "$REPO/bench/native_wasm_darwin.py" "$WORK/d2-rt-opt.ir" "$WORK/d2-rt-opt-darwin.ir" || fail 'D2 runtime: aarch64 conversion of the optimized module'
  for variant in plain opt; do
    if ! "$CN" "$WORK/d2-rt-$variant-darwin.ir" -o "$WORK/d2-rt-$variant-darwin" >"$WORK/d2-rt-$variant.build" 2>&1; then
      cat "$WORK/d2-rt-$variant.build"
      fail "D2 runtime: the $variant module does not build for aarch64"
    elif ! "$WORK/d2-rt-$variant-darwin" >"$WORK/d2-rt-$variant.out"; then
      fail "D2 runtime: the $variant aarch64 program exited with an error"
    fi
  done
  if cmp -s "$WORK/d2-rt-plain.out" "$WORK/d2-rt-opt.out" && [ -s "$WORK/d2-rt-plain.out" ]; then
    echo "  aarch64: the optimized program prints what the plain one prints ($(wc -l <"$WORK/d2-rt-plain.out" | tr -d ' ') lines)"
  else
    fail 'D2 runtime: aarch64 output differs from the unoptimized program'
  fi
  if [ -z "$WASMTIME_D2" ]; then
    host_limited 'D2 runtime: the wasm32-wasi module needs wasmtime'
  elif ! "$CN" "$WORK/d2-rt-opt.ir" -o "$WORK/d2-rt-opt.wasm" --target wasm32-wasi >"$WORK/d2-rt-wasm.build" 2>&1; then
    cat "$WORK/d2-rt-wasm.build"
    fail 'D2 runtime: the optimized module does not build for wasm32-wasi'
  elif ! "$WASMTIME_D2" run "$WORK/d2-rt-opt.wasm" >"$WORK/d2-rt-wasm.out" 2>"$WORK/d2-rt-wasm.err"; then
    cat "$WORK/d2-rt-wasm.err"
    fail 'D2 runtime: the wasm32-wasi module exited with an error'
  elif cmp -s "$WORK/d2-rt-plain.out" "$WORK/d2-rt-wasm.out"; then
    echo '  wasm32-wasi: the optimized module prints what the unoptimized aarch64 program prints'
  else
    fail 'D2 runtime: wasm output differs from the unoptimized program'
  fi
fi
