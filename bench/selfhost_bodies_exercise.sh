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
  if [ "$(basename "$fixture")" = "sem_bodies_ensure.iyi" ]; then
    cp "$fixture" "$WORK/ensure.cr"
    "$ORACLE" --bare "$WORK/ensure.cr" > "$WORK/o.txt" 2> "$WORK/o.err"
  elif [ "$(basename "$fixture")" = "sem_bodies_pointer_set.iyi" ]; then
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
  port_args=()
  if [ "$(basename "$fixture")" = "sem_bodies_defer.iyi" ]; then
    port_args=(--iyi-defer)
  fi
  if "$TYPED" "${port_args[@]}" "$fixture" "$REPO/src" > "$WORK/p.txt" 2> "$WORK/p.err"; then
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
echo "== 2d. Program defs share instances across callers without shadowing methods"
owner_fixture="$REPO/bench/fixtures/bodies_program_owner.iyi"
owner_probe="$WORK/program_owner_probe"
owner_expected="$WORK/program_owner.expected"
printf '%s\n' '*owner_probe<Int32>:Int32' '*owner_probe<String>:String' '*OwnerShadow#owner_probe<Int32>:Bool' | sort > "$owner_expected"
"$IYI" build -o "$owner_probe" "$REPO/bench/selfhost_program_owner_probe.iyi" > "$WORK/owner_build.log" 2>&1 || {
  cat "$WORK/owner_build.log"
  echo "  OWNER: failed to build probe"
  exit 1
}
if ! "$owner_probe" "$owner_fixture" "$REPO/src" > "$WORK/owner.unsorted" ||
   ! sort "$WORK/owner.unsorted" > "$WORK/owner.actual" ||
   ! diff -u "$owner_expected" "$WORK/owner.actual"; then
  echo "  OWNER: incorrect instance names or cache sharing"
  status=1
fi
if ! "$ORACLE" "$owner_fixture" > "$WORK/owner.oracle" 2> "$WORK/owner.oracle.err" ||
   ! "$TYPED" "$owner_fixture" "$REPO/src" > "$WORK/owner.typed" 2> "$WORK/owner.typed.err"; then
  echo "  OWNER: typing comparison could not run"
  status=1
else
  for line in 28 29 30; do
    grep "^${line}:.* Call " "$WORK/owner.oracle" | sort > "$WORK/owner.oracle.calls"
    grep "^${line}:.* Call " "$WORK/owner.typed" | sort > "$WORK/owner.typed.calls"
    if [ ! -s "$WORK/owner.oracle.calls" ] || ! diff -u "$WORK/owner.oracle.calls" "$WORK/owner.typed.calls"; then
      echo "  OWNER: call typing differs at line $line"
      status=1
    fi
  done
fi

echo
echo "== 2c. A call in a fun body's macro branch is typed after expansion"
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
  for name in sem_bodies_jumps sem_bodies_libcall sem_bodies_self_return sem_bodies_instance_cache sem_bodies_generic_ivar sem_bodies_import_scope sem_bodies_import_later sem_bodies_block_context sem_bodies_block_output sem_bodies_global_fun sem_bodies_magic_constant sem_bodies_fun_splice sem_bodies_block_nil_value sem_bodies_trait_def sem_bodies_proc_literal sem_bodies_proc_scope sem_bodies_class_method_constant sem_bodies_flow_truthy sem_bodies_flow_nil sem_bodies_flow_is_a sem_bodies_flow_early_exit sem_bodies_splat_restriction sem_bodies_generic_pointer_restriction sem_bodies_interpolation sem_bodies_union_restriction sem_bodies_pointer_set sem_bodies_nil_return sem_bodies_owner_typeof sem_bodies_enum_member sem_bodies_union_generic sem_bodies_virtual_lookup sem_bodies_receiver_order sem_bodies_unit_scope sem_bodies_unit_scope_inferred sem_bodies_proc_splat sem_bodies_pack_splat sem_bodies_imported_restriction; do
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
MAIN_VISITOR="$REPO/src/compiler/semantic/main_visitor.iyi"
owner_mutant_at_expected() {
  if ! "$IYI" build -o "$WORK/owner_mutant" "$REPO/bench/selfhost_program_owner_probe.iyi" > "$WORK/owner_mutant_build.log" 2>&1; then
    echo "INVALID MUTANT: owner probe failed to build" >&2
    cat "$WORK/owner_mutant_build.log" >&2
    if [ "${_PM_ARMED:-0}" = 1 ]; then return 0; fi
    return 1
  fi
  if ! "$WORK/owner_mutant" "$owner_fixture" "$REPO/src" > "$WORK/owner_mutant.unsorted" 2> "$WORK/owner_mutant_run.log"; then
    echo "INVALID MUTANT: owner probe failed to run" >&2
    cat "$WORK/owner_mutant_run.log" >&2
    if [ "${_PM_ARMED:-0}" = 1 ]; then return 0; fi
    return 1
  fi
  sort "$WORK/owner_mutant.unsorted" > "$WORK/owner_mutant.actual" || return 0
  diff -u "$owner_expected" "$WORK/owner_mutant.actual"
}
prove_mutation_all "program defs use their declared owner" "$MAIN_VISITOR" \
  "instance_owner = declared_owner if declared_owner.is_a?(SemanticProgram)" \
  "instance_owner = rec_type if declared_owner.is_a?(SemanticProgram)" -- owner_mutant_at_expected || status=1
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

# Assignment conditions carry the value's filters onto the assigned local.
flow_assign_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  local fixture="$REPO/bench/fixtures/sem_bodies_flow_assign.iyi"
  "$ORACLE" "$fixture" > "$WORK/flow_o.txt" 2>/dev/null || return 1
  "$MUT_TD" "$fixture" "$REPO/src" > "$WORK/flow_p.txt" 2>/dev/null || return 1
  sort "$WORK/flow_o.txt" > "$WORK/flow_o.sorted"
  sort "$WORK/flow_p.txt" > "$WORK/flow_p.sorted"
  local matched floor
  matched=$(comm -12 "$WORK/flow_o.sorted" "$WORK/flow_p.sorted" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_flow_assign.iyi" { print $2 }' "$FLOOR_FILE")
  [ "$matched" -ge "${floor:-0}" ]
}
prove_mutation "assignment condition narrows its target" "$MAIN_VISITOR" \
  "@type_filters = TypeFilters.assign_var(value_type_filters, v.name)" \
  "@type_filters = value_type_filters" -- flow_assign_at_floor || status=1

# A written ensure is refused with the iyi prelude; the handler mechanism is
# compared against the hosted compiler without that prelude.
ensure_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  local fixture="$REPO/bench/fixtures/sem_bodies_ensure.iyi"
  cp "$fixture" "$WORK/ensure.cr"
  "$ORACLE" --bare "$WORK/ensure.cr" > "$WORK/ensure_o.txt" 2>/dev/null || return 1
  "$MUT_TD" "$fixture" "$REPO/src" > "$WORK/ensure_p.txt" 2>/dev/null || return 1
  sort "$WORK/ensure_o.txt" > "$WORK/ensure_o.sorted"
  sort "$WORK/ensure_p.txt" > "$WORK/ensure_p.sorted"
  local matched floor
  matched=$(comm -12 "$WORK/ensure_o.sorted" "$WORK/ensure_p.sorted" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_ensure.iyi" { print $2 }' "$FLOOR_FILE")
  [ "$matched" -ge "${floor:-0}" ]
}
prove_mutation "ensure assignments reach following code" "$MAIN_VISITOR" \
  "          @vars[name] = type" \
  "          nil" -- ensure_at_floor || status=1

# The oracle and port both normalize this fixture with the iyi prelude mode.
defer_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  local fixture="$REPO/bench/fixtures/sem_bodies_defer.iyi"
  "$ORACLE" "$fixture" > "$WORK/defer_o.txt" 2>/dev/null || return 1
  "$MUT_TD" --iyi-defer "$fixture" "$REPO/src" > "$WORK/defer_p.txt" 2>/dev/null || return 1
  sort "$WORK/defer_o.txt" > "$WORK/defer_o.sorted"
  sort "$WORK/defer_p.txt" > "$WORK/defer_p.sorted"
  local matched floor
  matched=$(comm -12 "$WORK/defer_o.sorted" "$WORK/defer_p.sorted" | wc -l | tr -d ' ')
  floor=$(awk '$1 == "bench/fixtures/sem_bodies_defer.iyi" { print $2 }' "$FLOOR_FILE")
  [ "$matched" -ge "${floor:-0}" ]
}
prove_mutation "defer cleanup is typed" "$MAIN_VISITOR" \
  "      cleanup.accept(self)" \
  "      nil" -- defer_at_floor || status=1

ensure_refusal_check() {
  "$IYI" build -o "$WORK/ensure_refusal" "$REPO/bench/selfhost_ensure_refusal.iyi" > "$WORK/ensure_refusal_build.log" 2>&1 || return 1
  "$WORK/ensure_refusal"
}
echo "== 4c. Written ensure refusal and nested-loop exits"
ensure_refusal_check || status=1
prove_mutation "written ensure is refused under the prelude" "$MAIN_VISITOR" \
  "if @program.iyi_prelude? && !node.iyi_defer?" \
  "if false" -- ensure_refusal_check || status=1

# The return targets its instantiated def (hosted main_visitor.cr 2096).
ensure_targets_check() {
  "$IYI" build -o "$WORK/ensure_targets" "$REPO/bench/selfhost_ensure_targets.iyi" > "$WORK/ensure_targets_build.log" 2>&1 || return 1
  "$WORK/ensure_targets"
}
echo "== 4d. Return target identity"
ensure_targets_check || status=1
prove_mutation "return identifies its typed def" "$MAIN_VISITOR" \
  "    node.target = @current_def" \
  "    node.target = nil" -- ensure_targets_check || status=1
prove_mutation "break identifies its block call" "$MAIN_VISITOR" \
  "      node.target = @jump_block_calls[block]?" \
  "      node.target = nil" -- ensure_targets_check || status=1
prove_mutation "next identifies its block" "$MAIN_VISITOR" \
  "      node.target = block" \
  "      node.target = nil" -- ensure_targets_check || status=1
prove_mutation "captured next identifies its proc def" "$MAIN_VISITOR" \
  "    inner.current_def = def_node if def_node.captured_block?" \
  "    nil" -- ensure_targets_check || status=1

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
echo
echo "== 4d. A macro site in an enum method sees its constants"
macro_enum_facts_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  fixture="$REPO/bench/fixtures/sem_bodies_macro_enum_facts.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/eo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/ep.txt" || return 1
  matched=$(comm -12 "$WORK/eo.txt" "$WORK/ep.txt" | wc -l | tr -d ' ')
  [ "$matched" -ge 6 ]
}
prove_mutation_all "enum macro facts are not passed to the body splice" "$MAIN_VISITOR" \
  "MacroBindings.facts(@scope)" \
  "nil" -- macro_enum_facts_at_floor || status=1
macro_ivars_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  fixture="$REPO/bench/fixtures/sem_bodies_macro_ivars.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/eo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/ep.txt" || return 1
  matched=$(comm -12 "$WORK/eo.txt" "$WORK/ep.txt" | wc -l | tr -d ' ')
  [ "$matched" -ge 10 ]
}
prove_mutation "instance variable facts are not passed to the body splice" "$REPO/src/compiler/semantic/macro_bindings.iyi" \
  "facts.instance_vars_known = true" \
  "facts.instance_vars_known = false" -- macro_ivars_at_floor || status=1
macro_annotations_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  fixture="$REPO/bench/fixtures/sem_bodies_macro_annotations.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/eo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/ep.txt" || return 1
  matched=$(comm -12 "$WORK/eo.txt" "$WORK/ep.txt" | wc -l | tr -d ' ')
  [ "$matched" -ge 12 ]
}
prove_mutation "enum annotations are not supplied to macro sites" "$REPO/src/compiler/semantic/macro_bindings.iyi" \
  "facts.annotations_known = true" \
  "facts.annotations_known = false" -- macro_annotations_at_floor || status=1
macro_value_at_floor() {
  "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  fixture="$REPO/bench/fixtures/sem_bodies_macro_value.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/eo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/ep.txt" || return 1
  matched=$(comm -12 "$WORK/eo.txt" "$WORK/ep.txt" | wc -l | tr -d ' ')
  [ "$matched" -ge 9 ]
}
prove_mutation "a value-position macro expansion is not typed" "$MAIN_VISITOR" \
  "    expanded.accept(self)
    if et = child_type(expanded)" \
  "    nil
    if et = child_type(expanded)" -- macro_value_at_floor || status=1
macro_empty_at_floor() {
  if ! "$IYI" build -o "$MUT_TD" "$REPO/src/compiler/tools/typed_dump.iyi" > "$WORK/mut_build.log" 2>&1; then
    echo "INVALID MUTANT: typed dump did not build"
    cat "$WORK/mut_build.log"
    return 0
  fi
  fixture="$REPO/bench/fixtures/sem_bodies_macro_empty.iyi"
  "$ORACLE" "$fixture" 2>/dev/null | sort > "$WORK/eo.txt" || return 1
  "$MUT_TD" "$fixture" "$REPO/src" 2>/dev/null | sort > "$WORK/ep.txt" || return 1
  matched=$(comm -12 "$WORK/eo.txt" "$WORK/ep.txt" | wc -l | tr -d ' ')
  [ "$matched" -ge 18 ]
}
prove_mutation "an empty def-body macro is dropped, so the preceding expression types the def" "$REPO/src/compiler/semantic/inline_macros.iyi" \
  "        out << n if keep_empty" \
  "        nil" -- macro_empty_at_floor || status=1
macro_uninitialized_at_floor() {
  "$IYI" build -o "$WORK/macro_uninitialized" "$REPO/bench/selfhost_macro_uninitialized_exercise.iyi" > "$WORK/mut_build.log" 2>&1 || return 1
  "$WORK/macro_uninitialized" "$REPO/bench/fixtures/sem_bodies_macro_uninitialized.iyi"
}
macro_uninitialized_at_floor || status=1
prove_mutation "uninitialized locals are unavailable to later macro sites" "$REPO/src/compiler/semantic/inline_macros.iyi" \
  "  def visit(node : UninitializedVar) : Bool
    add_name(node.var)" \
  "  def visit(node : UninitializedVar) : Bool
    nil" -- macro_uninitialized_at_floor || status=1
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
  "  resolved = generic_of_typed_args(visitor, node)" \
  "  resolved = nil" -- generic_rebuild_at_floor || status=1
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
