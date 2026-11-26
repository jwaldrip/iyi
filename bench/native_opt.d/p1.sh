# Range proof fixtures, refusals, and mutations.
echo '== P1. range proof fixtures'
for name in p1_shift_loop p1_offset_unsigned p1_merged_check p1_widen_urem; do
  fixture_check prove "$name" changed
  fixture_stats prove "$FIXTURES/prove/$name.ir"
done
for name in p1_offset_zero p1_offset_overflow p1_merged_unknown_bound p1_merged_two_failures p1_merged_distinct_phi p1_widen_other_use p1_widen_unproven; do
  fixture_check prove "$name" keep
done

echo '== P1. range proof mutations'
prove_mutation 'P1-offset: zero does not prove a strict bound' src/compiler/ir/opt/prove.iyi \
  '    return if amount.nil? || amount <= 0_i64 # mutation P1-offset: zero does not imply strict inequality' \
  '    return if amount.nil? || amount < 0_i64 # mutation P1-offset: zero does not imply strict inequality' \
  -- mutation_check P1OFFSET prove p1_offset_zero || fail 'P1OFFSET was not caught'
mutation_result P1OFFSET
prove_mutation 'P1-edge: checked additions need the no-overflow edge' src/compiler/ir/opt/prove.iyi \
  '      return unless successor && @dom.dominates?(successor, owner_block(compare))' \
  '      return unless true' \
  -- mutation_check P1EDGE prove p1_offset_overflow || fail 'P1EDGE was not caught'
mutation_result P1EDGE
prove_mutation 'P1-bound: a merged bound must be nonnegative' src/compiler/ir/opt/prove.iyi \
  '    return if bound.lo < 0_i64 || bound.lo > bound.hi # mutation P1-bound: the bound is nonnegative' \
  '    return if bound.lo > bound.hi # mutation P1-bound: the bound is nonnegative' \
  -- mutation_check P1BOUND prove p1_merged_unknown_bound || fail 'P1BOUND was not caught'
mutation_result P1BOUND
prove_mutation 'P1-phi: failure edges must agree on phi values' src/compiler/ir/opt/prove.iyi \
  '      return false unless a && b && same?(a, b)' \
  '      return false unless a && b' \
  -- mutation_check P1PHI prove p1_merged_distinct_phi || fail 'P1PHI was not caught'
mutation_result P1PHI
prove_mutation 'P1-widen: a widened dividend must be nonnegative' src/compiler/ir/opt/prove.iyi \
  '    return false if dividend.lo < 0_i64 || dividend.lo > dividend.hi # mutation P1-widen: the operand is nonnegative' \
  '    return false if dividend.lo > dividend.hi # mutation P1-widen: the operand is nonnegative' \
  -- mutation_check P1WIDEN prove p1_widen_unproven || fail 'P1WIDEN was not caught'
mutation_result P1WIDEN
