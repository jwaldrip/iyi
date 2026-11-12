#!/usr/bin/env bash
# Fails when the iyi typing of type-shaped nodes in bodies (Generic, Union,
# ProcNotation, Metaclass, Self and FunDef, src/compiler/semantic/type_nodes.iyi)
# stops agreeing with the hosted pass, or when the type names those nodes print
# (GenericClassType, GenericInstanceType, union arguments) drift from it.
#
# Every fixture bench/fixtures/typenodes_*.iyi is analysed twice: by the
# hosted pass (bench/selfhost_typed_oracle.cr, --bare) and by the port's typed
# dump (src/compiler/tools/typed_dump.iyi). The two dumps must be byte-identical.
#
# The mutation proofs follow the rule the other selfhost gates use: each patch
# is applied to one file, the comparison must then diverge, and a patch that
# matched nothing is reported as proving nothing.
#
#   bash bench/selfhost_semantic_type_nodes_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
DUMP_SRC="$REPO/src/compiler/tools/typed_dump.iyi"
TYPE_NODES="$REPO/src/compiler/semantic/type_nodes.iyi"
TOP_LEVEL="$REPO/src/compiler/semantic/top_level.iyi"
TYPES_FILE="$REPO/src/compiler/types/types.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK/cache"

. "$REPO/bench/lib/mutation.sh"

ORACLE="$WORK/oracle"
DUMP="$WORK/typed_dump"

echo "== 1. Building the hosted oracle and the port's typed dump"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$ORACLE" "$REPO/bench/selfhost_typed_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; echo "FAILED to build the hosted oracle"; exit 1; }
"$IYI" build -o "$DUMP" "$DUMP_SRC" > "$WORK/dump_build.log" 2>&1 \
  || { cat "$WORK/dump_build.log"; echo "FAILED to build src/compiler/tools/typed_dump.iyi"; exit 1; }
echo "  built: oracle, typed_dump"

echo
echo "== 2. Each fixture: the port's typed dump against the hosted oracle"
fixture_count=0
diverged=0
total_nodes=0
for fixture in "$REPO"/bench/fixtures/typenodes_*.iyi; do
  base="$(basename "$fixture" .iyi)"
  fixture_count=$((fixture_count + 1))
  "$ORACLE" "$fixture" --bare > "$WORK/$base.oracle" 2> "$WORK/$base.oracle.err"
  if [ $? -ne 0 ]; then
    echo "  FAIL: the hosted oracle refused $base: $(head -n 1 "$WORK/$base.oracle.err")"
    diverged=$((diverged + 1))
    continue
  fi
  "$DUMP" "$fixture" > "$WORK/$base.port" 2>&1
  if cmp -s "$WORK/$base.oracle" "$WORK/$base.port"; then
    nodes=$(wc -l < "$WORK/$base.oracle" | tr -d ' ')
    total_nodes=$((total_nodes + nodes))
    echo "  ok: $base ($nodes typed nodes identical)"
  else
    echo "  FAIL: $base diverges from the hosted oracle:"
    diff "$WORK/$base.oracle" "$WORK/$base.port" | head -n 12
    diverged=$((diverged + 1))
  fi
done
echo "  Parity summary: $((fixture_count - diverged))/$fixture_count type-node fixtures match 100% ($total_nodes typed nodes compared)"
if [ "$fixture_count" -eq 0 ] || [ "$diverged" -ne 0 ]; then
  status=1
fi

# Rebuilds the port's typed dump from the (possibly mutated) source and compares
# it with the oracle outputs saved above. Returns non-zero on any divergence, or
# when the port does not build: both count as the mutation being caught.
check_outputs_match() {
  "$IYI" build -o "$WORK/mut_dump" "$DUMP_SRC" > "$WORK/mut_build.log" 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/typenodes_*.iyi; do
    base="$(basename "$fixture" .iyi)"
    "$WORK/mut_dump" "$fixture" > "$WORK/$base.mut" 2>&1
    cmp -s "$WORK/$base.oracle" "$WORK/$base.mut" || return 1
  done
  return 0
}

echo
echo "== 3. Guarded mutation proofs"
MUTATIONS_RUN=0

prove_mutation "generic is typed as its instance, not its metaclass" "$TYPE_NODES" \
  "meta = type_node_metaclass(instance)" \
  "meta = instance" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "type arguments are not bracketed as type arguments" "$TYPE_NODES" \
  "visitor.bracket_type_args(1)" \
  "visitor.bracket_type_args(0)" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "union type arguments print with their outer parentheses" "$TYPES_FILE" \
  "@type_args.map(&.arg_full_name)" \
  "@type_args.map(&.full_name)" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "unbound generic name drops its type variables" "$TOP_LEVEL" \
  '"#{base_full_name}(#{@type_vars.join(", ")})"' \
  '"#{base_full_name}"' \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "nilable cast is typed as its target without Nil" "$TYPE_NODES" \
  "visitor.program.type_merge(target.as(Type), visitor.program.nil_type)" \
  "target.as(Type)" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a generic in a type argument is typed as its metaclass" "$TYPE_NODES" \
  "  if visitor.in_type_args?" \
  "  if false" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "generic instance metaclass drops the generic class's class methods" "$TYPES_FILE" \
  "generic_instance_type.generic_type.as(GenericClassType).metaclass.defs" \
  "Hash(String, Array(Def)).new" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "pointerof types its operand, not a pointer to it" "$TYPE_NODES" \
  "visitor.set_type(node, type_node_system(visitor.program).pointer_of(t.as(Type)))" \
  "visitor.set_type(node, t.as(Type))" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "enum definition is not typed" "$REPO/src/compiler/semantic/main_visitor.iyi" \
  "visit_enum_def(self, node)" \
  "true" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "uninitialized local is recorded as Nil" "$TYPE_NODES" \
  "visitor.vars[name] = declared" \
  "visitor.vars[name] = visitor.program.nil_type" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "fun argument is typed from nothing, not the declared record" "$TYPE_NODES" \
  "vars[node.args[i].name] = arg_types[i]" \
  "vars[node.args[i].name] = visitor.program.nil_type" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "enum members are not walked before the enum is typed" "$TYPE_NODES" \
  "    member.accept(visitor)" \
  "    member.to_s" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST SEMANTIC TYPE-NODE CHECKS PASSED SUCCESSFULLY!"
else
  echo "SELFHOST SEMANTIC TYPE-NODE CHECKS FAILED"
fi
exit "$status"
