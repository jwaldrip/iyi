# L1: static unlikely edges and explicit branch-hint precedence.
echo '== L1. static branch layout'
fixture_check layout l1_sign_layout changed
fixture_stats layout "$FIXTURES/layout/l1_sign_layout.ir"
for name in l1_expect_wins l1_fp_keep l1_other_keep; do
  fixture_check layout "$name" keep
done

prove_mutation 'L1: static unlikely edges select the correct successor' src/compiler/ir/opt/layout.iyi \
  '    return @cfg.index(term.targets[0]) if unlikely_true # l1-static-unlikely' \
  '    return @cfg.index(term.targets[1]) if unlikely_true # l1-static-unlikely' \
  -- mutation_check L1Layout layout l1_sign_layout || fail 'L1 layout mutation was not caught'
mutation_result L1Layout
