#!/usr/bin/env bash
# Fails when the iyi transformers stop agreeing with the hosted ones they replace.
#
# Slice S1e of the native self-host (SPEC.md Phase S). The hosted transformers
# are src/compiler/iyi/semantic/{normalizer,literal_expander,cleanup_transformer,
# math_interpreter}.cr; the port lives in src/compiler/semantic/{normalizer,
# literal_expander,cleanup,math_interpreter}.iyi. Every fixture bench/fixtures/
# semtx_*.iyi is parsed, rewritten by the oracle (the hosted pipeline) and by the
# port, both dumped with the same AST printer, and required byte-identical.
# A check that ran only the port would pass for a transformer that rewrote
# nothing at all.
#
# Transform table: hosted transform -> port, as of this increment
# (every row is the normalizer; "not ported" names what the gate cannot see):
#   Program#normalize            NormalizerProgram.normalize          ported
#                                macro_expansion (skip of the expansion's
#                                own Expressions/Defer lowering)      not ported:
#                                needs the VirtualFile location check and
#                                MainVisitor#iyi_splice_macro_defers
#   Expressions                  transform(Expressions)               ported
#   Defer                        transform(Defer)                     ported
#   apply_defers                 apply_defers                         ported
#   Call (group, super, cmp)     transform(Call)                      ported
#   Call group propagated flag   expand_iyi_group(node, propagated)   ported
#   Def (block arg pruning)      transform(Def)                       ported
#   Macro                        transform(Macro)                     ported
#   If                           transform(If)                        ported
#   Propagate (!)                transform(Propagate)                 ported
#                                (error_construct "end!"); iyi_bang_call
#                                not ported: IsA has no such field
#   Recover                      transform(Recover)                   ported
#   Unless                       transform(Unless)                    ported
#   Until                        transform(Until)                     ported
#   Assign                       transform(Assign)                    ported
#   OpAssign (call/index/simple) transform(OpAssign) + helpers        ported
#   StringInterpolation          transform(StringInterpolation)       ported
#   Block (unpacks)              transform(Block)                     ported (fixed:
#                                the body merge duplicated the unpacks and a
#                                single-expression body was dropped)
#   Union                        transform(Union)                     ported
#
# Mutation proofs follow the rule the other selfhost gates use: each patched
# file is compared against the original, and a patch that matched nothing is
# reported as proving nothing rather than passing quietly.
#
#   bash bench/selfhost_semantic_transform_exercise.sh
set -u
status=0
diverged=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
NORM="$REPO/src/compiler/semantic/normalizer.iyi"
ORACLE_GATE="$REPO/bench/selfhost_normalizer_exercise.sh"
ORACLE_DRIVER="$REPO/bench/selfhost_normalizer_exercise.iyi"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO/bench/lib/mutation.sh"

# The AST printer both sides share. The hosted dump lives in the normalizer
# gate's heredoc and the port's in its driver; both are read from there so the
# printer cannot drift between gates. `TypeOf` is added to both: the expander
# writes one for every untyped literal, and an unlisted class would print only
# its name on one side.
TYPEOF_ORACLE='  when Iyi::TypeOf
    s = "#{p}TypeOf\n"
    node.expressions.each { |e| s += dump_ast(e, indent + 1) }
    s'
TYPEOF_PORT='    when TypeOf
      s = "#{p}TypeOf\n"
      node.expressions.each { |e| s += dump_ast(e, indent + 1) }
      s'

# Port driver: the printer module from the normalizer driver (its module
# header through the end of dump_ast), the TypeOf case inserted before the
# fallback, and this slice's own main.
gen_port_driver() {
  INS="$TYPEOF_PORT" awk '
    BEGIN { ins = ENVIRON["INS"] }
    NR <= 10 { print; next }
    NR >= 12 && NR <= 512 { buf[++n] = $0; next }
    END {
      for (i = 1; i <= n; i++) {
        if (buf[i] ~ /^    else$/ && buf[i + 1] ~ /ASTNode/) print ins
        print buf[i]
      }
      print "end"
    }' "$ORACLE_DRIVER"
  cat <<'PORT_MAIN'

if Program.args.size > 1 && Program.args[1] == "--count"
  filename = Program.args[0]
  source = File.read(filename)
  parser = Parser.new(source, filename)
  node = parser.parse
  prog = NormalizerProgram.new
  norm = prog.normalize(node)
  counter = NodeCounterVisitor.new
  norm.accept(counter)
  puts counter.count
else
  filename = Program.args[0]
  source = File.read(filename)
  parser = Parser.new(source, filename)
  node = parser.parse
  prog = NormalizerProgram.new
  norm = prog.normalize(node)
  print BenchSelfhostNormalizerExercise.dump_ast(norm)
end
PORT_MAIN
}

# Oracle driver: the hosted printer from the normalizer gate's heredoc (its
# dump_ast, its escape_s and its Counter), the TypeOf case inserted before the
# fallback, and this slice's own main. The heredoc is read from the normalizer
# gate so the two printers cannot drift.
gen_oracle_driver() {
  INS="$TYPEOF_ORACLE" awk '
    BEGIN { ins = ENVIRON["INS"] }
    /^cat <<.[A-Z_]*_GOLDEN_SCRIPT/ { inside = 1; next }
    inside && /^[A-Z_]*_GOLDEN_SCRIPT$/ { exit }
    inside && /^filename = ARGV\[0\]$/ { exit }
    inside { buf[++n] = $0; next }
    END {
      for (i = 1; i <= n; i++) {
        if (buf[i] ~ /node\.class\.name/) t = i
      }
      for (i = 1; i <= n; i++) {
        if (i == t - 1) print ins
        print buf[i]
      }
    }' "$ORACLE_GATE"
  cat <<'ORACLE_MAIN'

filename = ARGV[0]
src = File.read(filename)
parser = Iyi::Parser.new(src)
parser.filename = filename
node = parser.parse
node = Iyi::Program.new.normalize(node)

if ARGV.size > 1 && ARGV[1] == "--count"
  c = Counter.new
  node.accept(c)
  puts c.count
else
  print dump_ast(node)
end
ORACLE_MAIN
}

echo "== 1. Building the port driver and the hosted oracle"
gen_port_driver > "$WORK/semtx_port.iyi"
gen_oracle_driver > "$WORK/semtx_oracle.cr"
if ! grep -qF "when TypeOf" "$WORK/semtx_port.iyi" || ! grep -qF "when Iyi::TypeOf" "$WORK/semtx_oracle.cr"; then
  echo "  could not generate the shared AST printer from the normalizer gate"
  exit 1
fi
"$IYI" build -o "$WORK/port_exercise" "$WORK/semtx_port.iyi" || { echo "  PORT DRIVER DOES NOT BUILD"; exit 1; }
LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/dump_crystal" "$WORK/semtx_oracle.cr" || { echo "  HOSTED ORACLE DOES NOT BUILD"; exit 1; }
if [ ! -x "$WORK/dump_crystal" ]; then
  echo "  HOSTED ORACLE DOES NOT BUILD"
  exit 1
fi

echo
echo "== 2. Rewritten tree comparison against the hosted transformers"
fixture_count=0
total_matched_nodes=0
for fixture in "$REPO"/bench/fixtures/semtx_*.iyi; do
  fixture_name="bench/fixtures/$(basename "$fixture")"
  "$WORK/port_exercise" "$fixture" > "$WORK/iyi.ast" 2>"$WORK/iyi.err" || {
    echo "  $fixture_name: PORT FAILED"; cat "$WORK/iyi.err"; diverged=$((diverged + 1)); status=1; fixture_count=$((fixture_count + 1)); continue; }
  IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" > "$WORK/oracle.ast" 2>"$WORK/oracle.err" || {
    echo "  $fixture_name: HOSTED ORACLE FAILED"; cat "$WORK/oracle.err"; diverged=$((diverged + 1)); status=1; fixture_count=$((fixture_count + 1)); continue; }
  if ! cmp -s "$WORK/iyi.ast" "$WORK/oracle.ast"; then
    echo "  $fixture_name: REWRITTEN TREES DIFFER"
    diverged=$((diverged + 1))
    diff -u "$WORK/oracle.ast" "$WORK/iyi.ast" | head -40
    status=1
  else
    nodes_count=$(IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" --count)
    echo "  $fixture_name: identical ($nodes_count rewritten nodes match the hosted transformers)"
    total_matched_nodes=$((total_matched_nodes + nodes_count))
  fi
  fixture_count=$((fixture_count + 1))
done
echo "  Parity summary: $((fixture_count - diverged))/$fixture_count fixtures rewrite identically ($total_matched_nodes total nodes)"

echo
echo "== 3. Mutation proofs: each one must make the comparison above fail"
# A patch to the port that the gate must catch. The port driver is rebuilt
# from the patched normalizer and compared with the hosted oracle on every
# fixture; a build failure or any differing tree counts as caught.
MUTATIONS_RUN=0
check_transform_agrees() {
  "$IYI" build -o "$WORK/mut_port" "$WORK/semtx_port.iyi" > /dev/null 2>&1 || return 1
  for fixture in "$REPO"/bench/fixtures/semtx_*.iyi; do
    "$WORK/mut_port" "$fixture" > "$WORK/mut_iyi.ast" 2> /dev/null || return 1
    IYI_PATH="$REPO/src" "$WORK/dump_crystal" "$fixture" > "$WORK/mut_crystal.ast" || return 1
    cmp -s "$WORK/mut_iyi.ast" "$WORK/mut_crystal.ast" || return 1
  done
  return 0
}

MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "a group under a propagated bang keeps its join" "$NORM" 'rewritten << Call.new(group_var.clone, "join").at(node) unless propagated' 'rewritten << Call.new(group_var.clone, "join").at(node)' -- check_transform_agrees || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "a bang on a group does not mark it propagated" "$NORM" '@propagating_group = true' '@propagating_group = false' -- check_transform_agrees || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))
prove_mutation "the propagated mark is never consumed" "$NORM" 'propagated = @propagating_group' 'propagated = false' -- check_transform_agrees || status=1
echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST SEMANTIC TRANSFORM CHECKS PASSED SUCCESSFULLY!"
else
  echo "SELFHOST SEMANTIC TRANSFORM CHECKS FAILED"
fi
exit $status
