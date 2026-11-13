#!/usr/bin/env bash
# Body-typing fixtures (bench/fixtures/sem_bodies_*.iyi), S1d: each fixture is analysed
# by the hosted compiler's oracle (bench/selfhost_typed_oracle.cr, built here) and by the
# port's typed dump (src/compiler/tools/typed_dump.iyi, built here). A fixture's matched
# count is the number of oracle lines the port prints identically. Its floor
# (bench/selfhost_bodies.floor) may only rise.
#
#   bash bench/selfhost_bodies_exercise.sh
#
# Environment:
#   BODIES_RAISE=1   write each floor up to the measured count (never lower)
#
# Exit status 0 when every fixture reaches its floor, 1 otherwise.
set -u

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1
# The hosted compiler that builds the port's tools: this checkout's, or the one IYI_COMPILER names.
IYI="${IYI_COMPILER:-$REPO/bin/iyi}"
export IYI_PATH="$REPO/src"
CRYSTAL="${CRYSTAL:-crystal}"
FLOOR_FILE="$REPO/bench/selfhost_bodies.floor"
RAISE="${BODIES_RAISE:-0}"
WORK="$(mktemp -d)"
LC_ALL=C
export LC_ALL
export IYI_CACHE_DIR="$WORK/cache"
trap 'rm -rf "$WORK"' EXIT INT TERM
ORACLE="$WORK/oracle"
TYPED="$WORK/typed_dump"
RESULTS="$WORK/results.tsv"
status=0
: > "$RESULTS"

echo "== 1. Building the hosted compiler's oracle and the port's typed dump"
CRYSTAL_PATH="$REPO/src" IYI_CONFIG_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
  -o "$ORACLE" "$REPO/bench/selfhost_typed_oracle.cr" > "$WORK/oracle_build.log" 2>&1 \
  || { cat "$WORK/oracle_build.log"; echo "FAILED to build the oracle"; exit 1; }
"$IYI" build -o "$TYPED" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/typed_build.log" 2>&1 \
  || { cat "$WORK/typed_build.log"; echo "FAILED to build src/compiler/tools/typed_dump.iyi"; exit 1; }
echo "  built"

echo
echo "== 2. Each body fixture: the port's typed nodes against the oracle's"
for fixture in "$REPO"/bench/fixtures/sem_bodies_*.iyi; do
  rel="bench/fixtures/$(basename "$fixture")"
  # pointer_set defines Pointer#value= in the file. The prelude already has that
  # method, so this fixture is analysed alone.
  if [ "$(basename "$fixture")" = "sem_bodies_pointer_set.iyi" ]; then
    "$ORACLE" --bare "$fixture" > "$WORK/o.txt" 2> "$WORK/o.err"
  else
    "$ORACLE" "$fixture" > "$WORK/o.txt" 2> "$WORK/o.err"
  fi
  if [ $? -ne 0 ]; then
    printf '%s\t%s\t%s\n' "$rel" 0 "ORACLE: $(head -n 1 "$WORK/o.err")" >> "$RESULTS"
    continue
  fi
  sort "$WORK/o.txt" > "$WORK/o.sorted"
  nodes=$(wc -l < "$WORK/o.sorted" | tr -d ' ')
  if "$TYPED" "$fixture" "$REPO/src" > "$WORK/p.txt" 2> "$WORK/p.err"; then
    sort "$WORK/p.txt" > "$WORK/p.sorted"
    matched=$(comm -12 "$WORK/o.sorted" "$WORK/p.sorted" | wc -l | tr -d ' ')
  else
    matched=0
  fi
  printf '%s\t%s\t%s\n' "$rel" "$matched" "of $nodes oracle nodes" >> "$RESULTS"
done
awk -F'\t' '{ printf "  %-42s matched %4s  %s\n", $1, $2, $3 }' "$RESULTS"

echo
echo "== 3. Checking each fixture against its floor"
: > "$WORK/floor.new"
while IFS=$'\t' read -r rel matched note; do
  floor=$(awk -v r="$rel" '$1 == r { print $2 }' "$FLOOR_FILE" 2>/dev/null)
  floor=${floor:-0}
  if [ "$matched" -lt "$floor" ]; then
    echo "  BELOW FLOOR: $rel matched $matched, floor $floor. A regression: restore the typing or lower nothing."
    status=1
    keep=$floor
  elif [ "$matched" -gt "$floor" ]; then
    if [ "$RAISE" = 1 ]; then
      echo "  raised: $rel $floor to $matched"
      keep=$matched
    else
      echo "  RAISE THE FLOOR: $rel matched $matched, floor $floor (BODIES_RAISE=1)."
      status=1
      keep=$floor
    fi
  else
    keep=$floor
  fi
  case "$note" in ORACLE*)
    echo "  ORACLE: $rel: $note"
    status=1
    ;;
  esac
  printf '%s %s\n' "$rel" "$keep" >> "$WORK/floor.new"
done < "$RESULTS"

if [ "$RAISE" = 1 ]; then
  {
    echo "# body-typing fixture floors: <repo-relative fixture> <matched oracle nodes>."
    echo "# A count may only rise. Raise with: BODIES_RAISE=1 bash bench/selfhost_bodies_exercise.sh"
    sort "$WORK/floor.new"
  } > "$FLOOR_FILE"
fi

echo
echo "== 2b. The def-instance cache: one def at five call sites is three typed instances"
cache_fx="$REPO/bench/fixtures/sem_bodies_instance_cache.iyi"
cache_count=$("$TYPED" --instances "$cache_fx" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }')
echo "  sem_bodies_instance_cache.iyi typed instances: ${cache_count:-none} (expected 3)"
if [ "${cache_count:-}" != 3 ]; then
  echo "  CACHE: expected 3 typed instances, got ${cache_count:-none}"
  status=1
fi
refused_cache_count=$("$TYPED" --instances "$REPO/bench/fixtures/bodies_refused_cache.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }')
echo "  bodies_refused_cache.iyi typed instances: ${refused_cache_count:-none} (expected 1)"
if [ "${refused_cache_count:-}" != 1 ]; then
  echo "  CACHE: refused declared-return body was instantiated more than once"
  status=1
fi

echo
echo "== 2c. A call in a fun body's macro branch is typed only when the fun body is spliced"
splice_count=$("$TYPED" --instances "$REPO/bench/fixtures/sem_bodies_fun_splice.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }')
echo "  sem_bodies_fun_splice.iyi typed instances: ${splice_count:-none} (expected 1)"
if [ "${splice_count:-}" != 1 ]; then
  echo "  FUN SPLICE: expected 1 typed instance, got ${splice_count:-none}"
  status=1
fi
proc_scope_count=$("$TYPED" --instances "$REPO/bench/fixtures/sem_bodies_proc_scope.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }')
echo "  sem_bodies_proc_scope.iyi typed instances: ${proc_scope_count:-none} (expected 6)"
if [ "${proc_scope_count:-}" != 6 ]; then
  echo "  PROC SCOPE: expected both helper calls to be typed"
  status=1
fi

echo
echo "== 2d. A nilable property setter is the type of the value it is given"
setter_fx="$REPO/bench/fixtures/sem_bodies_setter_value.iyi"
"$ORACLE" "$setter_fx" > "$WORK/setter.hosted" 2> "$WORK/setter.hosted.err" || {
  echo "  ORACLE setter: $(head -n 1 "$WORK/setter.hosted.err")"
  status=1
}
if ! "$TYPED" "$setter_fx" "$REPO/src" > "$WORK/setter.port" 2> "$WORK/setter.port.err"; then
  echo "  PORT setter failed"
  status=1
elif ! diff -q "$WORK/setter.hosted" "$WORK/setter.port" >/dev/null; then
  echo "  setter value dump differs from hosted"
  diff -u "$WORK/setter.hosted" "$WORK/setter.port" | head -n 40
  status=1
else
  echo "  sem_bodies_setter_value.iyi matches hosted node by node"
fi

echo
echo "== 4. Mutation proofs: a patch to the port's body typing must drop a fixture below its floor"
. "$REPO/bench/lib/mutation.sh"
MUT_TD="$WORK/mut_typed_dump"
# The mutation runner captures check output and only displays its tail. Keep the
# compiler's complete diagnostics in the gate log when a mutant cannot build.
exec 9>&1
body_build_failed() {
  cat "$1" >&9
  if [ "${_PM_ARMED:-0}" -eq 1 ]; then
    echo "INVALID MUTANT: compiler build failed; this is not a behavioral catch"
    return 0
  fi
  echo "BASELINE FAILURE: compiler build failed"
  return 1
}
# Rebuilds the typed dump from the patched source and checks the lib-call and jump fixtures
# still reach their floors. Returns non-zero when a fixture falls below its floor.
bodies_at_floor() {
  if ! "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1; then
    body_build_failed "$WORK/mut_build.log"
    return $?
  fi
  for name in sem_bodies_jumps sem_bodies_libcall sem_bodies_self_return sem_bodies_instance_cache sem_bodies_generic_ivar sem_bodies_import_scope sem_bodies_import_later sem_bodies_block_context sem_bodies_block_output sem_bodies_global_fun sem_bodies_magic_constant sem_bodies_fun_splice sem_bodies_block_nil_value sem_bodies_trait_def sem_bodies_proc_literal sem_bodies_proc_scope sem_bodies_class_method_constant sem_bodies_flow_truthy sem_bodies_flow_nil sem_bodies_flow_is_a sem_bodies_flow_early_exit sem_bodies_splat_restriction sem_bodies_generic_pointer_restriction sem_bodies_interpolation sem_bodies_union_restriction sem_bodies_pointer_set sem_bodies_nil_return sem_bodies_owner_typeof sem_bodies_enum_member sem_bodies_union_generic sem_bodies_virtual_lookup sem_bodies_receiver_order sem_bodies_unit_scope sem_bodies_unit_scope_inferred sem_bodies_proc_splat sem_bodies_pack_splat sem_bodies_imported_restriction sem_bodies_setter_value sem_bodies_noreturn; do
    fixture="$REPO/bench/fixtures/$name.iyi"
    rel="bench/fixtures/$name.iyi"
    if [ "$name" = "sem_bodies_pointer_set" ]; then
      "$ORACLE" --bare "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
    else
      "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
    fi
    "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
    matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
    floor=$(awk -v r="$rel" '$1 == r { print $2 }' "$FLOOR_FILE" 2>/dev/null)
    [ "$matched" -ge "${floor:-0}" ] || return 1
  done
  count=$("$MUT_TD" --instances "$REPO/bench/fixtures/sem_bodies_instance_cache.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }') || return 1
  [ "${count:-}" = 3 ] || return 1
  fsc=$("$MUT_TD" --instances "$REPO/bench/fixtures/sem_bodies_fun_splice.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }') || return 1
  [ "${fsc:-}" = 1 ] || return 1
  proc_count=$("$MUT_TD" --instances "$REPO/bench/fixtures/sem_bodies_proc_scope.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }') || return 1
  [ "${proc_count:-}" = 6 ] || return 1
  refused_count=$("$MUT_TD" --instances "$REPO/bench/fixtures/bodies_refused_cache.iyi" "$REPO/src" 2>/dev/null | awk '/^typed instances:/ { print $3 }') || return 1
  [ "${refused_count:-}" = 1 ] || return 1
  return 0
}
# A nilable property setter is typed as the assigned value (hosted type_assign
# binds the Assign to the value, main_visitor.cr 1037-1038). Returns 0 only
# when that fixture's typed dump is identical to the hosted oracle.
setter_typed_as_value() {
  if ! "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/setter_mut_build.log" 2>&1; then
    body_build_failed "$WORK/setter_mut_build.log"
    return $?
  fi
  fx="$REPO/bench/fixtures/sem_bodies_setter_value.iyi"
  "$ORACLE" "$fx" > "$WORK/setter_mut.hosted" 2>/dev/null || return 1
  "$MUT_TD" "$fx" "$REPO/src" > "$WORK/setter_mut.port" 2>/dev/null || return 1
  diff -q "$WORK/setter_mut.hosted" "$WORK/setter_mut.port" >/dev/null
}
MAIN_VISITOR="$REPO/src/compiler/semantic/main_visitor.iyi"
prove_mutation "lib call result type" "$MAIN_VISITOR" \
  "set_type(node, target.result_type.as(Type))" \
  "set_type(node, @program.nil_type)" -- bodies_at_floor || status=1
prove_mutation "next value joins the block type" "$MAIN_VISITOR" \
  "blk_type = merge_jump_values(child_type(blk.body), @next_types)" \
  "blk_type = child_type(blk.body)" -- bodies_at_floor || status=1
prove_mutation "return value joins the def type" "$MAIN_VISITOR" \
  "body_type = merge_jump_values(child_type(body.as(ASTNode)), @return_types)" \
  "body_type = child_type(body.as(ASTNode))" -- bodies_at_floor || status=1
prove_mutation "self in a declared type names the receiver" "$MAIN_VISITOR" \
  "return o.as(Type) unless o.is_a?(SemanticProgram)" \
  "return @program unless o.is_a?(SemanticProgram)" -- bodies_at_floor || status=1
prove_mutation "a call hits the def-instance cache" "$MAIN_VISITOR" \
  "      return @def_instances[k]?" \
  "      return nil" -- bodies_at_floor || status=1
prove_mutation "a generic instance copies its declared instance variable with the argument" "$REPO/src/compiler/types/types.iyi" \
  "TypeQueries.replace_type_parameters(source_type, @type_vars)" \
  "source_type" -- bodies_at_floor || status=1
prove_mutation "an imported name is not in scope in its def's body" "$MAIN_VISITOR" \
  "enter_file_scope(target_def)" \
  "nil" -- bodies_at_floor || status=1
prove_mutation "a block body is typed in the scope of the call that owns it" "$MAIN_VISITOR" \
  "@scope = writer_scope" \
  "@scope = @program" -- bodies_at_floor || status=1
prove_mutation "a call to a top-level fun with a body is refused" "$MAIN_VISITOR" \
  "return visit_global_fun_call(node, global_fun) if own.empty?" \
  "return false if own.empty?" -- bodies_at_floor || status=1
prove_mutation "a fun body is not spliced at its top level" "$MAIN_VISITOR" \
  "splice_fun_body(node, @program.full_name)" \
  "nil" -- bodies_at_floor || status=1
prove_mutation "a trait definition is typed in its own type" "$MAIN_VISITOR" \
  "def visit(node : TraitDef) : Bool" \
  "def visit_trait_def_off(node : TraitDef) : Bool" -- bodies_at_floor || status=1
prove_mutation "a proc literal is typed as a Proc" "$MAIN_VISITOR" \
  "def visit(node : ProcLiteral) : Bool" \
  "def visit_proc_literal_off(node : ProcLiteral) : Bool" -- bodies_at_floor || status=1
prove_mutation "a call body is not typed in the scope of its owner" "$MAIN_VISITOR" \
  "    enter_owner_scope(body_receiver)" \
  "    nil" -- bodies_at_floor || status=1
prove_mutation "a block whose declared output is _ is checked against a type" "$MAIN_VISITOR" \
  "unless out_node.is_a?(Underscore)" \
  "unless false" -- bodies_at_floor || status=1
prove_mutation "__LINE__ is typed as a String" "$MAIN_VISITOR" \
  "if node.name == TokenKind::MAGIC_LINE || node.name == TokenKind::MAGIC_END_LINE" \
  "if false" -- bodies_at_floor || status=1
prove_mutation "if x narrows a truthy variable in its then branch" "$MAIN_VISITOR" \
  "    filter_vars(cond_type_filters)" \
  "    nil" -- bodies_at_floor || status=1
prove_mutation "if x.nil?, unless x and !x narrow the else branch" "$MAIN_VISITOR" \
  "    filter_vars(TypeFilters.invert(cond_type_filters))" \
  "    nil" -- bodies_at_floor || status=1
prove_mutation "while cond narrows its variable in the loop body" "$MAIN_VISITOR" \
  "      filter_vars(cond_type_filters)" \
  "      nil" -- bodies_at_floor || status=1
prove_mutation "early exit in then branch narrows the rest of the body" "$MAIN_VISITOR" \
  "        elsif then_unreachable" \
  "        elsif false" -- bodies_at_floor || status=1
prove_mutation "a refused body with declared return is cached" "$MAIN_VISITOR" \
  "        remember_def_instance(cache_key, target_def, declared_ret)" \
  "        nil" -- bodies_at_floor || status=1
prove_mutation "a generic pointer restriction is not bound from the receiver" "$MAIN_VISITOR" \
  "found = ArgRestriction.lookup_bound(type_node_system(@program), @current_type, restriction, owner)" \
  "found = LookupError.new(\"unbound\")" -- bodies_at_floor || status=1
prove_mutation "a splat call is not resolved by the calls lookup" "$MAIN_VISITOR" \
  "    return nil if target.error
    target.definition" \
  "    return nil if target.error
    nil" -- bodies_at_floor || status=1
prove_mutation "a union restriction is not instantiated from its members" "$MAIN_VISITOR" \
  "      return union_restriction_type(restriction.as(Union), rec_type)" \
  "      return nil" -- bodies_at_floor || status=1
prove_mutation "pointer_set types the assigned value" "$MAIN_VISITOR" \
  "set_type(node, pst)" \
  "set_type(node, @program.nil_type)" -- bodies_at_floor || status=1
prove_mutation "a Nil return annotation discards the body value" "$MAIN_VISITOR" \
  "unless declared_ret.nil_type? || bt.subtype_of?(declared_ret)" \
  "unless bt.subtype_of?(declared_ret)" -- bodies_at_floor || status=1
prove_mutation "a declared return whose body never returns is NoReturn" "$MAIN_VISITOR" \
  "      if bt.is_a?(NoReturnType)" \
  "      if declared_ret.nil_type? && bt.is_a?(NoReturnType)" -- bodies_at_floor || status=1
prove_mutation "metaclass owner binds its instance parameters" "$MAIN_VISITOR" \
  "found = ArgRestriction.lookup_bound(type_node_system(@program), @current_type, node, instance)" \
  "found = ArgRestriction.lookup_bound(type_node_system(@program), @current_type, node, owner)" -- bodies_at_floor || status=1
prove_mutation "typeof inside type arguments yields the instance type" "$REPO/src/compiler/semantic/type_nodes.iyi" \
  "  if depth > 0" \
  "  if false" -- bodies_at_floor || status=1
prove_mutation "enum members have the enum type" "$MAIN_VISITOR" \
  "        set_type(node, enum_type)" \
  "        set_type(node, @program.int32_type)" -- bodies_at_floor || status=1
prove_mutation "a generic union member retains its arguments" "$MAIN_VISITOR" \
  "    found = ArgRestriction.lookup_bound(type_node_system(@program), @current_type, restriction, owner)" \
  "    found = @program.lookup_type_node?(restriction, @current_type) || LookupError.new(\"not found\")" -- bodies_at_floor || status=1
prove_mutation "written class types are virtualized" "$MAIN_VISITOR" \
  "      return TypeQueries.virtual_type(quiet)" \
  "      return quiet" -- bodies_at_floor || status=1
prove_mutation "a call types its receiver before its arguments" "$MAIN_VISITOR" \
  "    rec_type : Type
    if obj = node.obj
      obj.accept(self)
      if ot = child_type(obj)
        rec_type = ot
      else
        @needs_type_filters = saved_call_ntf
        @type_filters = nil
        return false
      end
    else
      rec_type = @scope || @current_type
    end
    node.args.each do |arg|
      arg.accept(self)
    end" \
  "    node.args.each do |arg|
      arg.accept(self)
    end
    rec_type : Type
    if obj = node.obj
      obj.accept(self)
      if ot = child_type(obj)
        rec_type = ot
      else
        @needs_type_filters = saved_call_ntf
        @type_filters = nil
        return false
      end
    else
      rec_type = @scope || @current_type
    end" -- bodies_at_floor || status=1
prove_mutation "a proc literal inherits its enclosing scope" "$MAIN_VISITOR" \
  "    inner.scope = @scope" \
  "    inner.scope = @program" -- bodies_at_floor || status=1
prove_mutation "unit definitions resolve in their lexical scope" "$MAIN_VISITOR" \
  "      if mod.iyi_unit" \
  "      if false" -- bodies_at_floor || status=1
prove_mutation "splat arguments bind a tuple" "$MAIN_VISITOR" \
  "        param_type = tuple_type_of(@program, elements)" \
  "        param_type = @program.nil_type" -- bodies_at_floor || status=1
prove_mutation "imported restrictions use the defining unit" "$MAIN_VISITOR" \
  "        @current_type = owner if owner.iyi_unit" \
  "        nil" -- bodies_at_floor || status=1
prove_mutation "Assign typed as its target" "$MAIN_VISITOR" \
  "        set_type(node, val_type)
      elsif target_type.is_a?(GenericClassInstanceType)" \
  "        set_type(node, ivar.type)
      elsif target_type.is_a?(GenericClassInstanceType)" -- setter_typed_as_value || status=1


echo
echo "== 4b. A name no module defines is never typed in another module's def body (port only)"
leak_typed=$("$TYPED" "$REPO/bench/fixtures/bodies_scope_leak_b.iyi" "$REPO/src" 2>/dev/null | awk '$1 ~ /^5:/' | wc -l | tr -d ' ')
if [ "${leak_typed:-1}" -eq 0 ]; then
  echo "  refused: bodies_scope_leak_b.iyi line 5 (scope_value_nowhere) is untyped"
else
  echo "  NOT REFUSED: bodies_scope_leak_b.iyi line 5 has $leak_typed typed node(s)"
  status=1
fi

echo
echo "== 4c. A macro site in a def body sees the receiver's type parameters and the def's free variables"
# Rebuilds the typed dump from the patched source and checks the macro-bindings fixture alone.
macro_bindings_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_macro_bindings.iyi"
  rel="bench/fixtures/sem_bodies_macro_bindings.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk -v r="$rel" '$1 == r { print $2 }' "$FLOOR_FILE" 2>/dev/null)
  [ -n "${floor:-}" ] || return 1
  [ "$matched" -ge "$floor" ]
}
prove_mutation "a macro site in a def body does not see the receiver's type parameters" "$MAIN_VISITOR" \
  "    MacroBindings.of(@scope, free)" \
  "    MacroBindings.of(nil, free)" -- macro_bindings_at_floor || status=1
prove_mutation "a macro site in a def body does not see the def's free variables" "$MAIN_VISITOR" \
  "        @def_free_types[target_def] = free_types unless free_types.empty?" \
  "        nil" -- macro_bindings_at_floor || status=1
free_types_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_free_types.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_free_types.iyi" { print $2 }' "$FLOOR_FILE")
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
prove_mutation "a callee's free types are unavailable to body and return lookup" "$MAIN_VISITOR" \
  "found = ArgRestriction.lookup_free(type_node_system(@program), @current_type, node, owner, bound)" \
  "found = LookupError.new(\"unbound\")" -- free_types_at_floor || status=1
block_free_output_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_block_free_output.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_block_free_output.iyi" { print $2 }' "$FLOOR_FILE")
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
prove_mutation "block output binds its callee's free variable" "$MAIN_VISITOR" \
  "                        @def_free_types[cd] = bound" \
  "                        nil" -- block_free_output_at_floor || status=1
captured_free_output_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_capture_free_output.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_capture_free_output.iyi" { print $2 }' "$FLOOR_FILE")
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
prove_mutation "captured block output binds its callee's free variable" "$MAIN_VISITOR" \
  "                        @def_free_types[target_def] = bound unless bound.empty?" \
  "                        nil" -- captured_free_output_at_floor || status=1
generic_rebuild_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  touch "$WORK/imported_generic_mutant_built"
  fixture="$REPO/bench/fixtures/sem_bodies_owner_typeof.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_owner_typeof.iyi" { print $2 }' "$FLOOR_FILE")
  printf '%s of floor %s\n' "$matched" "$floor" > "$WORK/imported_generic_mutant_count"
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
rm -f "$WORK/imported_generic_mutant_built"
prove_mutation "a generic with typed arguments is rebuilt" "$REPO/src/compiler/semantic/type_nodes.iyi" \
  "    rebuilt = generic_of_typed_args(visitor, node)" \
  "    rebuilt = nil" -- generic_rebuild_at_floor || status=1
if [ "${MUTATION_SKIP:-0}" != 1 ] && [ ! -f "$WORK/imported_generic_mutant_built" ]; then
  echo "  FAIL: generic rebuild mutation did not build"
  status=1
fi
if [ -f "$WORK/imported_generic_mutant_count" ]; then
  echo "  generic rebuild mutant matched $(<"$WORK/imported_generic_mutant_count")"
fi
writer_type_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_block_writer_type.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_block_writer_type.iyi" { print $2 }' "$FLOOR_FILE")
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
prove_mutation "block body uses the writer's current type" "$MAIN_VISITOR" \
  "          @current_type = writer_type" \
  "          nil" -- writer_type_at_floor || status=1
captured_input_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  fixture="$REPO/bench/fixtures/sem_bodies_capture_none.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/mo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/mp.txt" || return 1
  matched=$(comm -12 "$WORK/mo.txt" "$WORK/mp.txt" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_capture_none.iyi" { print $2 }' "$FLOOR_FILE")
  [ -n "$floor" ] && [ "$matched" -ge "$floor" ]
}
prove_mutation "captured block parameters use restriction inputs" "$MAIN_VISITOR" \
  "                    @vars[arg.name] = input_types[index]" \
  "                    @vars[arg.name] = @program.nil_type" -- captured_input_at_floor || status=1
atomic_free_at_floor() {
  "$IYI" build -o "$WORK/atomic_tool" "$REPO/src/compiler/tools/compile_native.iyi" > "$WORK/mut_build.log" 2>&1 || { body_build_failed "$WORK/mut_build.log"; return $?; }
  rm -f "$WORK/atomic.refusals"
  "$WORK/atomic_tool" "$REPO/bench/fixtures/sem_bodies_match_atomics.iyi" \
    -o "$WORK/atomic" --pipeline typed --probe-phase --keep-going > "$WORK/atomic.log" 2>&1 || true
  [ -f "$WORK/atomic.refusals" ] || return 1
  awk -F '\t' '
    $1 == "body" && $2 ~ /^MatchAtomic\((UInt64|Int64)\)#(get|set|add|compare_and_set)$/ { bad = 1 }
    $1 == "reached" && $2 ~ /^MatchAtomic\((UInt64|Int64)\)#(get|set|add|compare_and_set)$/ { seen[$2] = 1 }
    END { for (name in seen) count++; exit bad || count != 8 }
  ' "$WORK/atomic.refusals"
}
if ! atomic_free_at_floor; then
  echo "  ATOMIC: one of the instantiated atomic bodies was refused or not reached"
  status=1
fi
prove_mutation "a resolved pointer restriction binds its free variable" "$MAIN_VISITOR" \
  "    if count_matches.any? { |d| !d.free_vars.nil? }" \
  "    if false" -- atomic_free_at_floor || status=1
if [ "$status" -eq 0 ]; then
  echo
  echo "== ALL BODY FIXTURES AT THEIR FLOORS"
else
  echo
  echo "== SOME BODY FIXTURE CHECKS FAILED"
fi
exit "$status"
