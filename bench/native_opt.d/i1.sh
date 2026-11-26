# I1: inliner hot loop sites and small leaves (contract C9). The ordinary cost gate is unchanged. Past it, a call inside a
# loop takes a callee of at most HOT_GATE, and any call takes a leaf of at most LEAF_GATE. Each callee is copied at most
# HOT_COPIES times by these two rules, and their growth stays within the group's hot allowance, max(2048, total // 16).
echo '== I1. hot loop sites and small leaves'
fixture_check inline i1_hot_loop changed
fixture_stats inline "$FIXTURES/inline/i1_hot_loop.ir"
fixture_check inline i1_hot_straight keep
# The copy cap admits twelve of the thirteen sites. A second run starts with a fresh budget and admits the thirteenth,
# so this fixture checks its golden and determinism, not idempotence.
unroll_fixture_check inline i1_hot_cap inline
fixture_check inline i1_leaf changed
fixture_stats inline "$FIXTURES/inline/i1_leaf.ir"
fixture_check inline i1_leaf_calls keep
fixture_check inline i1_leaf_loop keep
# The late group considers only allocation entries, so none of these calls is a candidate and none is copied.
fixture_check inline-alloc i1_late_group keep inline

# The allowance proof is generated under WORK, as section 2e generates its dispatch fixtures: pinning it in the tree
# would take thousands of lines. Eleven callees of cost 60 each grow the module by 16 per copy, with twelve callers of
# eleven calls each: 132 sites. The copy cap alone would admit 132 copies. The allowance admits 128 (128 x 16 = 2,048)
# and leaves 4 calls, so exactly 4 calls to the callees remain and 695 sink calls appear (55 in the callee bodies and 5
# per admitted copy). A padding function keeps the module budget (1.5 x its size) from binding first.
I1_ALLOW_RETAINED=4
I1_ALLOW_SINKS=695
i1_allowance_file() {
  local dir="$WORK/i1-fixtures" file
  file="$dir/i1_hot_allowance.ir"
  mkdir -p "$dir" || return 2
  "$PY" - "$(native_path "$file")" <<'PY' || return 2
import sys

out = sys.argv[1]
CALLEES = 11
CALLERS = 12
PAD = 4400
lines = ['; iyi-ir 1', 'source_filename = "i1_hot_allowance"',
         'target triple = "aarch64-apple-darwin"',
         'target datalayout = "e-m:o-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-n32:64-S128-Fn32"',
         'declare external void @sink()']
for j in range(CALLEES):
    lines.append('define internal i64 @w%d(i64 %%x) {' % j)
    lines.append('entry:')
    lines += ['  call void () @sink()'] * 5
    prev = '%x'
    for i in range(1, 10):
        lines.append('  %%a%d = add i64 %s, %d' % (i, prev, i))
        prev = '%%a%d' % i
    lines.append('  ret i64 %s' % prev)
    lines.append('}')
for c in range(CALLERS):
    lines.append('define external i64 @c%d(i64 %%n) {' % c)
    lines += ['entry:', '  br label %head', 'head:',
              '  %i = phi i64 [ 0, label %entry ], [ %next, label %body ]',
              '  %acc = phi i64 [ 0, label %entry ], [ %acc3, label %body ]',
              '  %c = icmp slt i64 %i, %n',
              '  br i1 %c, label %body, label %done', 'body:']
    prev = '%i'
    for j in range(CALLEES):
        lines.append('  %%v%d = call i64 (i64) @w%d(i64 %s)' % (j, j, prev))
        prev = '%%v%d' % j
    lines += ['  %%acc3 = add i64 %%acc, %s' % prev, '  %next = add i64 %i, 1', '  br label %head',
              'done:', '  ret i64 %acc', '}']
lines.append('define external i64 @padding(i64 %x) {')
lines.append('entry:')
for i in range(PAD):
    lines.append('  %%p%d = add i64 %%x, %d' % (i, i))
lines += ['  ret i64 %x', '}']
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines) + '\n')
PY
  printf '%s\n' "$file"
}

# Prints "<retained callee calls> <sink calls>" for one run of a driver, or run-failed.
i1_allowance_counts() {
  local driver="$1" file="$2" out="$WORK/i1-allowance.ir" err="$WORK/i1-allowance.err"
  if ! "$driver" run --verify-each inline "$(native_path "$file")" >"$out" 2>"$err"; then
    echo run-failed
    return 0
  fi
  awk '/call i64 \(i64\) @w[0-9]+\(/ { retained++ } /call void \(\) @sink\(\)/ { sinks++ }
       END { printf "%d %d\n", retained + 0, sinks + 0 }' "$out"
}

i1_allowance_check() {
  local file counts
  file=$(i1_allowance_file) || { fail 'I1 allowance fixture could not be written'; return; }
  counts=$(i1_allowance_counts "$DRV" "$file")
  if [ "$counts" != "$I1_ALLOW_RETAINED $I1_ALLOW_SINKS" ]; then
    fail "inline/i1_hot_allowance: retained and sink calls are '$counts', pinned at $I1_ALLOW_RETAINED $I1_ALLOW_SINKS"
    return
  fi
  echo "  ok: inline/i1_hot_allowance (retained $I1_ALLOW_RETAINED calls, $I1_ALLOW_SINKS sink calls)"
}

# A mutation check for the allowance: caught when the mutant's counts differ from the pinned ones.
i1_allowance_mutant_check() {
  local status="$WORK/I1Allow.status" file counts
  printf '2\n' >"$status"
  build_driver "$MUTANT" || return 2
  file=$(i1_allowance_file) || return 2
  counts=$(i1_allowance_counts "$MUTANT" "$file")
  [ "$counts" = run-failed ] && return 2
  if [ "$counts" = "$I1_ALLOW_RETAINED $I1_ALLOW_SINKS" ]; then
    printf '0\n' >"$status"
    return 0
  fi
  printf '1\n' >"$status"
  return 1
}

i1_allowance_check

prove_mutation 'I1.1: a call outside a loop takes a hot callee' src/compiler/ir/opt/inline.iyi \
  '  cost <= HOT_GATE && loops.depth(origin) >= 1' \
  '  cost <= HOT_GATE # mutation I1-depth: the loop depth is ignored' \
  -- mutation_check I1Depth inline i1_hot_straight || fail 'I1 depth mutation was not caught'
mutation_result I1Depth
prove_mutation 'I1: copies of one callee are capped' src/compiler/ir/opt/inline.iyi \
  '    hot_copies(callee) < HOT_COPIES && @hot_used + growth <= @hot_limit' \
  '    @hot_used + growth <= @hot_limit # mutation I1-cap: copies of one callee are not capped' \
  -- mutation_check I1Cap inline i1_hot_cap || fail 'I1 copy-cap mutation was not caught'
mutation_result I1Cap
prove_mutation 'I1: the hot allowance is checked' src/compiler/ir/opt/inline.iyi \
  '    hot_copies(callee) < HOT_COPIES && @hot_used + growth <= @hot_limit' \
  '    hot_copies(callee) < HOT_COPIES # mutation I1-allowance: the hot allowance is not checked' \
  -- i1_allowance_mutant_check || fail 'I1 allowance mutation was not caught'
mutation_result I1Allow
prove_mutation 'I1.2: a call disqualifies a leaf' src/compiler/ir/opt/inline.iyi \
  '      callee.blocks[k].insts.each { |inst| return false if inst.op == Op::Call }' \
  '      callee.blocks[k].insts.each { |inst| return false if false } # mutation I1-leaf: a call does not disqualify a leaf' \
  -- mutation_check I1Leaf inline i1_leaf_calls || fail 'I1 leaf-call mutation was not caught'
mutation_result I1Leaf
prove_mutation 'I1.2: a loop disqualifies a leaf' src/compiler/ir/opt/inline.iyi \
  '    return false if loops.depth(k) > 0' \
  '    return false if false # mutation I1-loop: a loop does not disqualify a leaf' \
  -- mutation_check I1Loop inline i1_leaf_loop || fail 'I1 leaf-loop mutation was not caught'
mutation_result I1Loop
