# S1: small folds and bounded, speculatable diamond conversion.
echo '== S1. small IR folds'
for name in s1_nil_select s1_overflow_zero s1_parity; do
  fixture_check simplify "$name" changed
done
for name in s1_select_variable_arm s1_overflow_two s1_parity_by_three; do
  fixture_check simplify "$name" keep
done
for name in s1_diamond_select s1_triangle_select s1_keep_forward_empty; do
  fixture_check cfg-simplify "$name" changed
done
for name in s1_diamond_load s1_diamond_div s1_diamond_call s1_diamond_three s1_diamond_aggregate s1_diamond_extra_pred s1_diamond_poison s1_diamond_loop_header s1_keep_thread_into_bool_phi s1_keep_thread_phi_used_elsewhere s1_keep_thread_side_effect s1_keep_thread_two_phis; do
  fixture_check cfg-simplify "$name" keep
done
for name in s1_nil_select s1_overflow_zero s1_parity; do
  fixture_stats simplify "$FIXTURES/simplify/$name.ir"
done
for name in s1_diamond_select s1_triangle_select; do
  fixture_stats cfg-simplify "$FIXTURES/cfg-simplify/$name.ir"
done

prove_mutation 'S1.1: select arms are not swapped' src/compiler/ir/opt/simplify.iyi \
  '    first = int_value(sel.args[1])
    second = int_value(sel.args[2])' \
  '    first = int_value(sel.args[2])
    second = int_value(sel.args[1])' \
  -- mutation_check S1M1 simplify s1_nil_select || fail 'S1M1 was not caught'
mutation_result S1M1
prove_mutation 'S1.2: checked multiplication by two is not neutral' src/compiler/ir/opt/simplify.iyi \
  '      elsif !(a.type.bits == 1 && id == IntrinsicId::SMulOverflow) && integer_is?(b, 1)' \
  '      elsif !(a.type.bits == 1 && id == IntrinsicId::SMulOverflow) && (integer_is?(b, 1) || int_value(b) == 2_i64)' \
  -- mutation_check S1M2 simplify s1_overflow_two || fail 'S1M2 was not caught'
mutation_result S1M2
prove_mutation 'S1.3: divisor three is not a power of two' src/compiler/ir/opt/simplify.iyi \
  '    return nil if divisor.nil? || divisor <= 1_i64 || (divisor & (divisor &- 1_i64)) != 0_i64' \
  '    return nil if divisor.nil? || divisor <= 1_i64 || ((divisor & (divisor &- 1_i64)) != 0_i64 && divisor != 3_i64)' \
  -- mutation_check S1M3 simplify s1_parity_by_three || fail 'S1M3 was not caught'
mutation_result S1M3
prove_mutation 'S1.4: a load is not speculatable' src/compiler/ir/opt/cfg_simplify.iyi \
  '  return false unless pure?(inst) && !inst.type.void?' \
  '  return false unless (pure?(inst) || inst.op == Op::Load) && !inst.type.void?' \
  -- mutation_check S1M4 cfg-simplify s1_diamond_load || fail 'S1M4 was not caught'
mutation_result S1M4
