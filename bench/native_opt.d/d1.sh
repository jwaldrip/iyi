# D1: the late dispatch-chain pass, refusals, scale and mutation proofs.
echo '== D1. switch chains'
for name in d1_concrete d1_head_prefix d1_default_phis d1_duplicate d1_phi_wide_same d1_phi_undef_same; do
  fixture_check switch-chain "$name" changed
done
for name in d1_three d1_two_selectors d1_range_arm d1_extra_inst d1_used_compare d1_wide \
            d1_duplicate_phi d1_phi_conflict d1_phi_wide_conflict d1_phi_undef_mixed d1_nonconstant d1_literal_selector d1_multi_dispatch d1_multiple_predecessors; do
  fixture_check switch-chain "$name" keep
done
fixture_stats switch-chain "$FIXTURES/switch-chain/d1_concrete.ir"
fixture_stats switch-chain "$FIXTURES/switch-chain/d1_default_phis.ir"

# The pass is release-only and its boundary is reachable in either direction.
if "$DRV" run --verify-each --stop-before switch-chain release "$FIXTURES/switch-chain/d1_concrete.ir" >"$WORK/d1-before.ir" &&
   grep -q 'icmp eq' "$WORK/d1-before.ir" &&
   "$DRV" run --verify-each --stop-before simplify switch-chain,simplify "$FIXTURES/switch-chain/d1_concrete.ir" >"$WORK/d1-after.ir" &&
   grep -q 'switch i32' "$WORK/d1-after.ir" &&
   "$DRV" run --verify-each default "$FIXTURES/switch-chain/d1_concrete.ir" >"$WORK/d1-default.ir" &&
   ! grep -q 'switch i32' "$WORK/d1-default.ir"; then
  echo '  ok: D1 release-only pass and stop-before boundaries'
else
  fail 'D1 release-only pass or stop-before boundary'
fi

# Each arm returns directly, so parsing and relinking do not build a quadratic
# predecessor list on a shared join. Compare the least of five CPU readings:
# an occupied or efficiency core must not turn a linear pass into a false fail.
d1_scale_check() {
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
source_filename = "d1_scale"
target triple = "aarch64-apple-darwin"
target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"
define external void @dispatch(i32 %x) {
'''

def make(count):
    path = os.path.join(work, 'd1-scale-%d.ir' % count)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(header)
        for i in range(count):
            name = 'entry' if i == 0 else 'b%d' % i
            following = 'end' if i + 1 == count else 'b%d' % (i + 1)
            f.write('%s:\n  %%c%d = icmp eq i32 %%x, %d\n  br i1 %%c%d, label %%a%d, label %%%s\n'
                    % (name, i, i, i, i, following))
        for i in range(count):
            f.write('a%d:\n  ret void\n' % i)
        f.write('end:\n  unreachable\n}\n')
    return path

def cpu_time(n, path, env):
    if os.name != 'nt':
        before = resource.getrusage(resource.RUSAGE_CHILDREN)
    proc = subprocess.Popen([binary, 'run', '--no-verify', 'switch-chain', path],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        out, err = proc.communicate(timeout=60)
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
    if b'switch i32 %x' not in out or b'br i1' in out:
        raise RuntimeError('scale chain was not converted')
    return elapsed

try:
    paths = {n: make(n) for n in (2000, 4000)}
    times = {2000: [], 4000: []}
    env = dict(os.environ, GC_MARKERS='1', GC_NPROCS='1')
    for _ in range(5):
        for n in (2000, 4000):
            times[n].append(cpu_time(n, paths[n], env))
    small = min(times[2000])
    large = min(times[4000])
    if small <= 0:
        raise RuntimeError('scale timer returned zero')
    ratio = large / small
    print('  d1 scale: 2000=%.6fs 4000=%.6fs ratio=%.3f (least of 5 CPU runs)' % (small, large, ratio))
    if ratio > 2.5:
        print('decisive: D1 scale ratio %.3f exceeds 2.5' % ratio)
        sys.exit(1)
except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
    print('FAIL: D1 scale:', exc, file=sys.stderr)
    sys.exit(2)
PY
}

d1_scale_mutation() {
  if ! build_driver "$MUTANT"; then
    echo "D1 scale mutant did not build" >&2
    cat "$WORK/build.log" >&2
    return 2
  fi
  d1_scale_check "$MUTANT"
}

if d1_scale_check "$DRV"; then
  prove_mutation 'D1: a quadratic chain rescan exceeds the scale bound' src/compiler/ir/opt/switch_chain.iyi \
    '      tests << next_test' \
    $'      scan_round = 0\n      while scan_round < 16\n        scan = 0\n        while scan < tests.size\n          return false unless same_selector?(tests[scan].selector, first.selector)\n          scan = scan + 1\n        end\n        scan_round = scan_round + 1\n      end\n      tests << next_test' \
    -- d1_scale_mutation || fail 'D1 scale mutation was not caught'
else
  fail 'D1 scale contract failed'
fi

prove_mutation 'D1: every comparison uses the same SSA selector' src/compiler/ir/opt/switch_chain.iyi \
  '  a == b # mutation D1-selector: require one SSA selector' \
  '  a.type == b.type # mutation: admit different selectors' \
  -- mutation_check D1Selector switch-chain d1_two_selectors || fail 'D1 selector mutation was not caught'
mutation_result D1Selector
prove_mutation 'D1: a chain has at least four comparisons' src/compiler/ir/opt/switch_chain.iyi \
  'MIN_CHAIN = 4 # mutation D1-threshold: at least four tests' \
  'MIN_CHAIN = 2 # mutation: two comparisons suffice' \
  -- mutation_check D1Threshold switch-chain d1_three || fail 'D1 threshold mutation was not caught'
mutation_result D1Threshold
prove_mutation 'D1: phi inputs name the new predecessor' src/compiler/ir/opt/switch_chain.iyi \
  '              blocks << head # mutation D1-phi: the incoming predecessor is the head' \
  '              blocks << from # mutation: retain the deleted predecessor' \
  -- mutation_check D1Phi switch-chain d1_default_phis || fail 'D1 phi mutation was not caught'
mutation_result D1Phi
