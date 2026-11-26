# M1: transparent loops, certain-to-run header loads and memory boundaries.
echo '== M1. loop-invariant loads'
for name in m1_sum_loop m1_probe_loop m1_raise_call m1_nested_store m1_preheader_call \
            m1_body_field_out_of_bounds m1_body_different_struct \
            m1_body_partial_object m1_header_fault_order; do
  fixture_check licm "$name" changed
  fixture_stats licm "$FIXTURES/licm/$name.ir"
done
for name in m1_store_in_loop m1_call_in_loop m1_marking_flag m1_marking_escape \
            m1_marking_derived m1_nested_inner_store m1_variant_pointer m1_undef_pointer \
            m1_body_no_witness m1_header_call m1_memory_boundaries; do
  fixture_check licm "$name" keep
done

prove_mutation 'M1: a store makes its loop nontransparent' src/compiler/ir/opt/licm.iyi \
  '    writes_memory?(inst) || opaque?(inst) || marking_read?(inst) ||
      (!terminator_op?(inst.op) && has_side_effects?(inst))' \
  '    (inst.op != Op::Store && writes_memory?(inst)) || opaque?(inst) || marking_read?(inst) ||
      (!terminator_op?(inst.op) && inst.op != Op::Store && has_side_effects?(inst))' \
  -- mutation_check M1Store licm m1_store_in_loop || fail 'M1 store mutation was not caught'
mutation_result M1Store

prove_mutation 'M1: a load must be certain to run' src/compiler/ir/opt/licm.iyi \
  '    return -1 if loop_id < 0 || @headers[loop_id] != block || !loop_transparent?(loop_id)' \
  '    return -1 if loop_id < 0 || !loop_transparent?(loop_id)' \
  -- mutation_check M1Body licm m1_body_no_witness || fail 'M1 body mutation was not caught'
mutation_result M1Body

prove_mutation 'M1: a header call may leave before the load' src/compiler/ir/opt/licm.iyi \
  '    return true if inst.op == Op::Call # mutation M1Call: calls may leave the block' \
  '    return false if inst.op == Op::Call # mutation M1Call: calls may leave the block' \
  -- mutation_check M1Call licm m1_header_call || fail 'M1 call mutation was not caught'
mutation_result M1Call
