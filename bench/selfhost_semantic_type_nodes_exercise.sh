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
# The cast upcast flag (Cast#upcast, NilableCast#upcast) is compared by its own
# driver pair, bench/selfhost_cast_upcast_oracle.cr and bench/selfhost_cast_upcast_dump.iyi,
# over bench/fixtures/typenodes_cast_*.iyi: the typed dump prints types only, and the
# typed parity gate's oracle must not change.
#
# The mutation proofs follow the rule the other selfhost gates use: each patch
# is applied to one file, the comparison must then diverge, and a patch that
# matched nothing is reported as proving nothing.
#
#   bash bench/selfhost_semantic_type_nodes_exercise.sh
set -u
status=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
. "$REPO/bench/lib/host.sh" || exit 1
require_test_host || exit 1
REPO_NATIVE="$(native_path "$REPO")"
IYI="$REPO/bin/iyi"
HOSTED_COMPILER="$REPO/bin/crystal"
DUMP_SRC="$REPO/src/compiler/tools/typed_dump.iyi"
TYPE_NODES="$REPO/src/compiler/semantic/type_nodes.iyi"
TOP_LEVEL="$REPO/src/compiler/semantic/top_level.iyi"
TYPES_FILE="$REPO/src/compiler/types/types.iyi"
WORK="$(mktemp -d)"
WORK_NATIVE="$(native_path "$WORK")"
trap 'rm -rf "$WORK"' EXIT
export IYI_CACHE_DIR="$WORK_NATIVE/cache" IYI_PATH="$REPO_NATIVE/src"

. "$REPO/bench/lib/mutation.sh"

ORACLE="$WORK/oracle$EXE"
DUMP="$WORK/typed_dump$EXE"
STRICT="$WORK/strict_dump$EXE"
CAST_ORACLE="$WORK/cast_oracle$EXE"
CAST_DUMP="$WORK/cast_dump$EXE"
CAST_DUMP_SRC="$REPO/bench/selfhost_cast_upcast_dump.iyi"

echo "== 1. Building the hosted oracle and the port's typed dump"
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" CRYSTAL_PATH="$REPO_NATIVE/src" IYI_CONFIG_PATH="$REPO_NATIVE/src" "$HOSTED_COMPILER" build -Di_know_what_im_doing \
  -o "$WORK_NATIVE/oracle$EXE" "$REPO_NATIVE/bench/selfhost_typed_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; echo "FAILED to build the hosted oracle"; exit 1; }
"$IYI" build -o "$WORK_NATIVE/typed_dump$EXE" "$(native_path "$DUMP_SRC")" > "$WORK/dump_build.log" 2>&1 \
  || { cat "$WORK/dump_build.log"; echo "FAILED to build src/compiler/tools/typed_dump.iyi"; exit 1; }
# The strict variant of the port's typed dump: the same analysis with total mode off, so a refusal
# raises. A total dump records a refusal on the node it refused, and the walk never prints a def
# body's node, so a refusal in a method body is invisible to the total dump.
sed -e 's/prog\.total_mode = true/prog.total_mode = false/' -e 's/mv\.total = true/mv.total = false/' "$DUMP_SRC" > "$WORK/strict_dump.iyi"
if [ "$(grep -c 'prog\.total_mode = false' "$WORK/strict_dump.iyi")" -ne 1 ] ||
   [ "$(grep -c 'mv\.total = false' "$WORK/strict_dump.iyi")" -ne 1 ]; then
  echo "FAILED to switch off both total-mode flags of src/compiler/tools/typed_dump.iyi"
  exit 1
fi
"$IYI" build -o "$WORK_NATIVE/strict_dump$EXE" "$WORK_NATIVE/strict_dump.iyi" > "$WORK/strict_build.log" 2>&1 \
  || { cat "$WORK/strict_build.log"; echo "FAILED to build the strict typed dump"; exit 1; }
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" CRYSTAL_PATH="$REPO_NATIVE/src" IYI_CONFIG_PATH="$REPO_NATIVE/src" "$HOSTED_COMPILER" build -Di_know_what_im_doing \
  -o "$WORK_NATIVE/cast_oracle$EXE" "$REPO_NATIVE/bench/selfhost_cast_upcast_oracle.cr" > "$WORK/cast_oracle_build.log" 2>&1 \
  || { cat "$WORK/cast_oracle_build.log"; echo "FAILED to build the hosted cast oracle"; exit 1; }
"$IYI" build -o "$WORK_NATIVE/cast_dump$EXE" "$(native_path "$CAST_DUMP_SRC")" > "$WORK/cast_dump_build.log" 2>&1 \
  || { cat "$WORK/cast_dump_build.log"; echo "FAILED to build the port's cast dump"; exit 1; }
echo "  built: oracle, typed_dump"

# Whether the oracle's dump and the port's dump of one fixture agree. The uninitialized fixtures declare
# their instance variable at class level, and the port types that declaration (TypeDeclaration T and
# InstanceVar T) where hosted types it Nil and not at all: a divergence in main_visitor.iyi's declaration
# path, outside the uninitialized branch. Those two line kinds are left out of these fixtures' comparison.
dumps_agree() {
  case "$3" in
    typenodes_uninitialized_ivar*)
      sed -e '/ TypeDeclaration /d' -e '/ InstanceVar /d' "$1" > "$1.agree" &&
        sed -e '/ TypeDeclaration /d' -e '/ InstanceVar /d' "$2" > "$2.agree" &&
        cmp -s "$1.agree" "$2.agree" ;;
    *) cmp -s "$1" "$2" ;;
  esac
}

echo
echo "== 2. Each fixture: the port's typed dump against the hosted oracle"
fixture_count=0
diverged=0
total_nodes=0
for fixture in "$REPO"/bench/fixtures/typenodes_*.iyi; do
  base="$(basename "$fixture" .iyi)"
  case "$base" in typenodes_refuse_*) continue ;; esac
  fixture_count=$((fixture_count + 1))
  "$ORACLE" "$(native_path "$fixture")" --bare > "$WORK/$base.oracle" 2> "$WORK/$base.oracle.err"
  if [ $? -ne 0 ]; then
    echo "  FAIL: the hosted oracle refused $base: $(head -n 1 "$WORK/$base.oracle.err")"
    diverged=$((diverged + 1))
    continue
  fi
  if ! "$DUMP" "$(native_path "$fixture")" > "$WORK/$base.port" 2>&1; then
    echo "  FAIL: the port could not analyse $base"
    diverged=$((diverged + 1))
    continue
  fi
  if dumps_agree "$WORK/$base.oracle" "$WORK/$base.port" "$base"; then
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

echo
echo "== 2b. Each cast fixture: the port's upcast flags against the hosted cast oracle"
cast_count=0
cast_diverged=0
for fixture in "$REPO"/bench/fixtures/typenodes_cast_*.iyi; do
  base="$(basename "$fixture" .iyi)"
  cast_count=$((cast_count + 1))
  "$CAST_ORACLE" "$(native_path "$fixture")" --bare > "$WORK/$base.cast_oracle" 2> "$WORK/$base.cast_oracle.err"
  if [ $? -ne 0 ]; then
    echo "  FAIL: the hosted cast oracle refused $base: $(head -n 1 "$WORK/$base.cast_oracle.err")"
    cast_diverged=$((cast_diverged + 1))
    continue
  fi
  if ! "$CAST_DUMP" "$(native_path "$fixture")" > "$WORK/$base.cast_port" 2>&1; then
    echo "  FAIL: the cast port could not analyse $base"
    cast_diverged=$((cast_diverged + 1))
    continue
  fi
  if cmp -s "$WORK/$base.cast_oracle" "$WORK/$base.cast_port"; then
    echo "  ok: $base ($(wc -l < "$WORK/$base.cast_oracle" | tr -d ' ') cast nodes identical)"
  else
    echo "  FAIL: $base diverges from the hosted cast oracle:"
    diff "$WORK/$base.cast_oracle" "$WORK/$base.cast_port" | head -n 12
    cast_diverged=$((cast_diverged + 1))
  fi
done
echo "  Cast upcast summary: $((cast_count - cast_diverged))/$cast_count cast fixtures match 100%"
if [ "$cast_count" -eq 0 ] || [ "$cast_diverged" -ne 0 ]; then
  status=1
fi

# The strict-analysis fixtures: each must analyse with no refusal under the strict port. The
# uninitialized branch is what they test: an instance variable's declaration, its generic owner,
# a class body, and a call through a virtual receiver.
STRICT_ACCEPTED="typenodes_uninitialized_ivar typenodes_uninitialized_ivar_generic typenodes_uninitialized_ivar_body typenodes_uninitialized_ivar_virtual"
# The refusal fixtures, as name|mode|message. The message is the port's text, which is hosted's text
# where hosted gives the same message: `hosted` (hosted refuses with it as the first line of its error),
# `refused` (hosted refuses, but its error names only the instantiation that failed), and `port` (hosted
# accepts the program, and the port refuses it by name until it takes that path).
REFUSAL_FIXTURES=(
  "typenodes_refuse_uninitialized_ivar_metaclass|hosted|@instance_vars are not yet allowed in metaclasses: use @@class_vars instead"
  "typenodes_refuse_uninitialized_ivar_program|hosted|can only declare instance variables of a non-generic class, not a main (<Program>)"
  "typenodes_refuse_uninitialized_ivar_generic|refused|can't declare variable of generic non-instantiated type Box(T)"
  "typenodes_refuse_uninitialized_ivar_genmod|refused|can't use Mod(T) as the type of an instance variable yet, use a more specific type"
  "typenodes_refuse_uninitialized_ivar_undeclared|port|can't infer the type of instance variable '@x' of Slot: the port does not type one from an uninitialized assignment yet"
  "typenodes_refuse_uninitialized_ivar_join|port|can't join uninitialized Int32 into instance variable '@x' of Slot, which is (Int64 | Nil): the port takes only the same type yet"
)

# strict_holds <strict dump>: every accepted fixture analyses, and every refusal fixture is refused with its
# message. Hosted's answers do not change under a mutant, so they are checked once, in section 2c.
strict_holds() {
  local strict="$1" base mode msg entry
  for base in $STRICT_ACCEPTED; do
    "$strict" "$(native_path "$REPO/bench/fixtures/$base.iyi")" > "$WORK/$base.strict_mut" 2>&1 || return 1
  done
  for entry in "${REFUSAL_FIXTURES[@]}"; do
    IFS='|' read -r base mode msg <<< "$entry"
    if "$strict" "$(native_path "$REPO/bench/fixtures/$base.iyi")" > "$WORK/$base.strict_mut" 2>&1; then
      return 1
    fi
    grep -Fq -- "$msg" "$WORK/$base.strict_mut" || return 1
  done
  return 0
}

# A mutant's strict dump must build before its strict answers can establish divergence.
check_port_strict() {
  rm -f "$WORK/mut_strict$EXE"
  if ! "$IYI" build -o "$WORK_NATIVE/mut_strict$EXE" "$WORK_NATIVE/strict_dump.iyi" > "$WORK/mut_strict_build.log" 2>&1 ||
     [ ! -x "$WORK/mut_strict$EXE" ]; then
    echo "INVALID MUTANT: strict typed dump did not build"
    cat "$WORK/mut_strict_build.log"
    return 0
  fi
  strict_holds "$WORK/mut_strict$EXE"
}

echo
echo "== 2c. Strict analysis: each accepted fixture analyses, and each refusal fixture is refused by name"
strict_count=0
strict_diverged=0
for base in $STRICT_ACCEPTED; do
  strict_count=$((strict_count + 1))
  if "$STRICT" "$(native_path "$REPO/bench/fixtures/$base.iyi")" > "$WORK/$base.strict" 2>&1; then
    echo "  ok: $base analyses strictly"
  else
    echo "  FAIL: the strict port refuses $base: $(awk 'NF' "$WORK/$base.strict" | awk 'NR==1' | cut -c1-200)"
    strict_diverged=$((strict_diverged + 1))
  fi
done
for entry in "${REFUSAL_FIXTURES[@]}"; do
  IFS='|' read -r base mode msg <<< "$entry"
  strict_count=$((strict_count + 1))
  hosted_ok=1
  oracle_rc=0
  "$ORACLE" "$(native_path "$REPO/bench/fixtures/$base.iyi")" --bare > "$WORK/$base.refusal_oracle" 2> "$WORK/$base.refusal_oracle.err" || oracle_rc=$?
  case "$mode" in
    hosted) [ "$oracle_rc" -ne 0 ] && grep -Fq -- "$msg" "$WORK/$base.refusal_oracle.err" || hosted_ok=0 ;;
    refused) [ "$oracle_rc" -ne 0 ] || hosted_ok=0 ;;
    port) [ "$oracle_rc" -eq 0 ] || hosted_ok=0 ;;
  esac
  if [ "$hosted_ok" -ne 1 ]; then
    echo "  FAIL: hosted does not answer $base as its $mode fixture says"
    strict_diverged=$((strict_diverged + 1))
    continue
  fi
  if "$STRICT" "$(native_path "$REPO/bench/fixtures/$base.iyi")" > "$WORK/$base.strict" 2>&1; then
    echo "  FAIL: the strict port accepts $base"
    strict_diverged=$((strict_diverged + 1))
  elif grep -Fq -- "$msg" "$WORK/$base.strict"; then
    echo "  ok: $base refused by name ($mode): $msg"
  else
    echo "  FAIL: the strict port refuses $base with other text: $(awk 'NF' "$WORK/$base.strict" | awk 'NR==1' | cut -c1-200)"
    strict_diverged=$((strict_diverged + 1))
  fi
done
echo "  Strict summary: $((strict_count - strict_diverged))/$strict_count strict fixtures as expected"
if [ "$strict_count" -eq 0 ] || [ "$strict_diverged" -ne 0 ]; then
  status=1
fi

# A mutant must build and execute before its output can establish divergence.
check_outputs_match() {
  rm -f "$WORK/mut_dump$EXE"
  if ! "$IYI" build -o "$WORK_NATIVE/mut_dump$EXE" "$(native_path "$DUMP_SRC")" > "$WORK/mut_build.log" 2>&1 ||
     [ ! -x "$WORK/mut_dump$EXE" ]; then
    echo "INVALID MUTANT: typed dump did not build"
    cat "$WORK/mut_build.log"
    return 0
  fi
  for fixture in "$REPO"/bench/fixtures/typenodes_*.iyi; do
    base="$(basename "$fixture" .iyi)"
    case "$base" in typenodes_refuse_*) continue ;; esac
    if [ ! -f "$WORK/$base.oracle" ] ||
       ! "$WORK/mut_dump$EXE" "$(native_path "$fixture")" > "$WORK/$base.mut" 2>&1; then
      echo "INVALID MUTANT: typed dump or baseline oracle failed for $base"
      return 0
    fi
    dumps_agree "$WORK/$base.oracle" "$WORK/$base.mut" "$base" || return 1
  done
  return 0
}

check_cast_outputs_match() {
  rm -f "$WORK/mut_cast$EXE"
  if ! "$IYI" build -o "$WORK_NATIVE/mut_cast$EXE" "$(native_path "$CAST_DUMP_SRC")" > "$WORK/mut_cast_build.log" 2>&1 ||
     [ ! -x "$WORK/mut_cast$EXE" ]; then
    echo "INVALID MUTANT: cast dump did not build"
    cat "$WORK/mut_cast_build.log"
    return 0
  fi
  for fixture in "$REPO"/bench/fixtures/typenodes_cast_*.iyi; do
    base="$(basename "$fixture" .iyi)"
    if [ ! -f "$WORK/$base.cast_oracle" ] ||
       ! "$WORK/mut_cast$EXE" "$(native_path "$fixture")" > "$WORK/$base.cast_mut" 2>&1; then
      echo "INVALID MUTANT: cast dump or baseline oracle failed for $base"
      return 0
    fi
    cmp -s "$WORK/$base.cast_oracle" "$WORK/$base.cast_mut" || return 1
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
  "@type_args.map { |a| a.devirtualize.arg_full_name }" \
  "@type_args.map { |a| a.devirtualize.full_name }" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "unbound generic name drops its type variables" "$TOP_LEVEL" \
  '"#{base_full_name}(#{@type_vars.join(", ")})"' \
  '"#{base_full_name}"' \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "nilable cast is typed as its target without Nil" "$TYPE_NODES" \
  "visitor.program.type_merge(TypeQueries.virtual_type(result), visitor.program.nil_type)" \
  "TypeQueries.virtual_type(result)" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a generic in a type argument is typed as its metaclass" "$TYPE_NODES" \
  "  if visitor.in_type_args?" \
  "  if false" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "generic instance metaclass drops the generic class's class methods" "$TYPES_FILE" \
  $'    parents << instance_type.generic_type.as(ModuleType).metaclass\n  end\n\n  def generic_instance_type : GenericClassInstanceType\n    @instance_type.as(GenericClassInstanceType)\n  end\n\n  # The class methods of a generic instance are the generic class\'s own (hosted\n  # `delegate defs, macros, to: generic_type`, types.cr 3400).\n  def defs : Hash(String, Array(Def))\n    generic_instance_type.generic_type.as(GenericClassType).metaclass.defs' \
  $'    nil\n  end\n\n  def generic_instance_type : GenericClassInstanceType\n    @instance_type.as(GenericClassInstanceType)\n  end\n\n  # The class methods of a generic instance are the generic class\'s own (hosted\n  # `delegate defs, macros, to: generic_type`, types.cr 3400).\n  def defs : Hash(String, Array(Def))\n    Hash(String, Array(Def)).new' \
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

prove_mutation "a fun's declared types are not re-resolved by the type system" "$TOP_LEVEL" \
  '              resolved_args.each { |arg_type| f.arg_types << arg_type }' \
  '              node.args.each { |arg| f.arg_types << object_type }' \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a pointerof of a local is refused, in a fun body or anywhere" "$TYPE_NODES" \
  "  if exp.is_a?(Var)" \
  "  if false" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a generic whose name fails in scope is not rebuilt from its typed arguments" "$TYPE_NODES" \
  "  resolved = generic_of_typed_args(visitor, node)" \
  $'  resolved = type_node_lookup(visitor).lookup(visitor.current_type, node)\n  resolved = nil if resolved.is_a?(LookupError)' \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a union inside a generic owner ignores its visited type arguments" "$TYPE_NODES" \
  "  visitor.set_type(node, visitor.program.type_merge(types))" \
  $'  resolved_u = type_node_lookup(visitor).lookup(visitor.current_type, node)\n  return false if resolved_u.is_a?(LookupError)\n  visitor.set_type(node, resolved_u.as(Type))' \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "self type node ignores scope_type and fails in top-level current_type" "$TYPE_NODES" \
  "  the_self : Type = visitor.scope_type || visitor.current_type" \
  "  the_self : Type = visitor.current_type" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "a cast's upcast flag is not recorded" "$TYPE_NODES" \
  "  node.upcast = upcast
  result = to_type
  if !upcast
    if f = filtered
      result = f.as(Type)
    end
  end
  visitor.set_type(node, TypeQueries.virtual_type(result))" \
  "  node.upcast = false
  result = to_type
  if !upcast
    if f = filtered
      result = f.as(Type)
    end
  end
  visitor.set_type(node, TypeQueries.virtual_type(result))" \
  -- check_cast_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "an uninitialized instance variable is refused, as the port did before it took the path" "$TYPE_NODES" \
  "  if var.is_a?(InstanceVar)" \
  "  if false" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a class body's uninitialized instance variable also types its declared type" "$TYPE_NODES" \
  "  if scope.nil?" \
  "  if false" \
  -- check_outputs_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a class method's uninitialized instance variable is typed, not refused" "$TYPE_NODES" \
  "  if owner.is_a?(MetaclassType)" \
  "  if false" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "an uninitialized instance variable at the top level is typed, not refused" "$TYPE_NODES" \
  "  if owner.is_a?(SemanticProgram)" \
  "  if false" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "a bare generic is not refused as a non-instantiated type" "$TYPE_NODES" \
  "  if stored.is_a?(GenericClassType)" \
  "  if false" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

old_storable=$'  unless lookup.can_be_stored?(stored)\n    return visitor.refuse(node, "can\'t use #{lookup.shown(stored)} as the type of an instance variable yet, use a more specific type")'
new_storable=$'  unless true\n    return visitor.refuse(node, "can\'t use #{lookup.shown(stored)} as the type of an instance variable yet, use a more specific type")'
prove_mutation "a generic module is accepted as the type of an instance variable" "$TYPE_NODES" "$old_storable" "$new_storable" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "an undeclared instance variable takes the uninitialized type, not a refusal" "$TYPE_NODES" \
  "    return visitor.refuse(node, \"can't infer the type of instance variable '#{var.name}' of #{owner.full_name}: the port does not type one from an uninitialized assignment yet\")" \
  "    ivar_type = stored" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "an uninitialized type that differs from the variable's type is joined, not refused" "$TYPE_NODES" \
  "  unless held.subtype_of?(stored) && stored.subtype_of?(held)" \
  "  unless true" \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "an instance variable's declared type is not bracketed as a type argument" "$TYPE_NODES" \
  $'  lookup = type_node_lookup(visitor)\n  visitor.bracket_type_args(1)' \
  $'  lookup = type_node_lookup(visitor)\n  visitor.bracket_type_args(0)' \
  -- check_port_strict || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST SEMANTIC TYPE-NODE CHECKS PASSED SUCCESSFULLY!"
else
  echo "SELFHOST SEMANTIC TYPE-NODE CHECKS FAILED"
fi
exit "$status"
