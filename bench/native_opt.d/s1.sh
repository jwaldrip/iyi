# S1: small folds in simplify (constant-select compare, neutral checked arithmetic, remainder parity).
echo '== S1. small IR folds'
for name in s1_nil_select s1_overflow_zero s1_parity; do
  fixture_check simplify "$name" changed
done
for name in s1_select_variable_arm s1_overflow_two s1_parity_by_three; do
  fixture_check simplify "$name" keep
done
for name in s1_nil_select s1_overflow_zero s1_parity; do
  fixture_stats simplify "$FIXTURES/simplify/$name.ir"
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
