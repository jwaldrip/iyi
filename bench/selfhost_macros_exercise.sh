#!/usr/bin/env bash
# Fails when the iyi macro engine stops agreeing with the one it replaces.
#
# Every fixture is expanded by each implementation site by site: the text each
# top-level `{% %}` and `{{ }}` site expands to, in source order, with where it
# is written. How the expansion ended (a skip, or a raise with its message and
# location) and the whole output follow. The two dumps are required
# byte-identical.
#
# A fixture whose header is `# refuse: <name>` names a macro method the port
# refuses by name. The oracle is not run on it (it would run the command); the
# port must report the refusal.
#
# The mutation proofs follow the rule the other selfhost gates use: the patched
# file is compared against the original, and a patch that matched nothing is
# reported as proving nothing rather than passing quietly.
#
#   bash bench/selfhost_macros_exercise.sh
set -eu
status=0
diverged=0
REPO="$(cd "$(dirname "$0")/.." && pwd)"
IYI="$REPO/bin/iyi"
CRYSTAL="${CRYSTAL:-crystal}"
INTERP="$REPO/src/compiler/macros/interpreter.iyi"
PARSER="$REPO/src/compiler/macros/macro_parser.iyi"
ENGINE="$REPO/src/compiler/macros/engine.iyi"
. "$REPO/bench/lib/mutation.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== 1. Building and running the macro engine exercise"
"$IYI" build -o "$WORK/exercise" "$REPO/bench/selfhost_macros_exercise.iyi"
"$WORK/exercise" > "$WORK/plain.out" 2>&1
cat "$WORK/plain.out"
if ! grep -qF "ALL SELFHOST MACRO CHECKS PASSED SUCCESSFULLY!" "$WORK/plain.out"; then
  echo "  EXERCISE FAILED"
  status=1
fi

echo
echo "== Checking reported verification counts in plain mode"
for phrase in \
  "testing macro argument substitution... ok" \
  "testing macro splats and double splats... ok" \
  "testing macro control flow (if, unless, elsif, else)... ok" \
  "testing macro iteration (for over arrays, tuples, named tuples, ranges)... ok" \
  "testing macro stringification and identifier methods... ok" \
  "testing macro AST node methods... ok" \
  "testing macro fresh variable generation... ok" \
  "testing macro code and definition generation... ok" \
  "ALL SELFHOST MACRO CHECKS PASSED SUCCESSFULLY!"; do
  if ! grep -qF "$phrase" "$WORK/plain.out"; then
    echo "  MISSING REPORTED CHECK: '$phrase'"
    status=1
  else
    echo "  verified report: '$phrase'"
  fi
done

echo
echo "== 2. Per-site expansion dump: the oracle and the port must print the same bytes"
cat <<'CRYSTAL_GOLDEN_SCRIPT' > "$WORK/dump_crystal_macro.cr"
require "compiler/requires"

# iyi: the line and column a TypeException was raised at, which the hosted
# class keeps in instance variables. The gate reads them through methods added
# here, in the oracle driver only; `CodeError` is abstract, so its own
# variables cannot be typed from here.
module Iyi
  class TypeException
    def gate_line : Int32
      @line_number || 0
    end

    def gate_column : Int32
      @column_number || 0
    end
  end
end

def escape_s(s : String) : String
  res = "\""
  i = 0
  while i < s.bytesize
    case s.byte_at(i).chr
    when '\n' then res += "\\n"
    when '\r' then res += "\\r"
    when '\t' then res += "\\t"
    when '\\' then res += "\\\\"
    when '"'  then res += "\\\""
    else res += s.byte_at(i).chr.to_s
    end
    i += 1
  end
  res + "\""
end

class NodeCounter < Iyi::Visitor
  getter count = 0
  def visit(node : Iyi::ASTNode)
    @count += 1
    true
  end
end

args = ARGV.to_a
filename = ""
count = false
host = false
target = ""
defines = [] of String
i = 0
while i < args.size
  a = args[i]
  if a == "--count"
    count = true
  elsif a == "--host-target"
    host = true
  elsif a == "--target"
    i += 1
    target = args[i]
  elsif a == "-D"
    i += 1
    defines << args[i]
  else
    filename = a
  end
  i += 1
end

if host
  puts Iyi::Config.host_target.to_s
  exit 0
end

src = File.read(filename)
parser = Iyi::Parser.new(src)
node = parser.parse

the_macro : Iyi::Macro? = nil
the_call : Iyi::Call? = nil

def find_nodes(node : Iyi::ASTNode, the_macro : Iyi::Macro?, the_call : Iyi::Call?)
  case node
  when Iyi::Expressions
    node.expressions.each do |e|
      the_macro, the_call = find_nodes(e, the_macro, the_call)
    end
  when Iyi::Macro
    the_macro = node
  when Iyi::Call
    the_call = node if the_macro && the_call.nil?
  end
  {the_macro, the_call}
end

the_macro, the_call = find_nodes(node, nil, nil)
program = Iyi::Program.new
unless target.empty?
  program.codegen_target = Iyi::Codegen::Target.new(target)
end
defines.each { |d| program.flags << d }

# The same interpreter `Program#expand_macro` builds, driven one top-level
# site at a time so each site's text can be read back.
interp = Iyi::MacroInterpreter.new(program, program, program, the_macro.not_nil!, the_call.not_nil!, nil, in_macro: true)
body = the_macro.not_nil!.body
nodes = [] of Iyi::ASTNode
if body.is_a?(Iyi::Expressions)
  body.expressions.each { |e| nodes << e }
else
  nodes << body
end

lines = [] of String
skipped = false
failure : {Int32, Int32, String}? = nil
nodes.each do |site|
  break if skipped || failure
  before = interp.to_s.bytesize
  begin
    interp.accept(site)
  rescue ex : Iyi::SkipMacroException
    skipped = true
    next
  rescue ex : Iyi::TypeException
    failure = {ex.gate_line, ex.gate_column, ex.message.to_s}
    next
  end
  next if site.is_a?(Iyi::MacroLiteral)
  after = interp.to_s
  text = after.byte_slice(before, after.bytesize - before)
  line = 0
  column = 0
  if loc = site.location
    line = loc.line_number
    column = loc.column_number
  end
  kind = site.class.name.split("::").last
  lines << "site #{lines.size} #{kind} #{line}:#{column} text=#{escape_s(text)}"
end

if count
  puts lines.size
else
  lines.each { |l| puts l }
  puts "skipped" if skipped
  if f = failure
    puts "error #{f[0]}:#{f[1]} message=#{escape_s(f[2])}"
  end
  puts "output text=#{escape_s(interp.to_s)}"
end
CRYSTAL_GOLDEN_SCRIPT

LLVM_CONFIG="${LLVM_CONFIG:-$(command -v llvm-config || true)}" \
  CRYSTAL_PATH="$REPO/src" "$CRYSTAL" build -Di_know_what_im_doing \
    -o "$WORK/dump_crystal" "$WORK/dump_crystal_macro.cr"
if [ ! -x "$WORK/dump_crystal" ]; then
  echo "  THE ORACLE DID NOT BUILD: this gate cannot conclude anything"
  exit 1
fi

# The host triple is the hosted compiler's own. A fixture names another with a
# `# target: <triple>` line and its `-D` defines with `# define: <name>` lines.
HOST_TRIPLE="$("$WORK/dump_crystal" --host-target)"
if [ -z "$HOST_TRIPLE" ]; then
  echo "  THE ORACLE REPORTED NO HOST TRIPLE: this gate cannot conclude anything"
  exit 1
fi
fixture_args() {
  awk -v host="$HOST_TRIPLE" '
    /^# target: / { t = $3 }
    /^# define: / { d = d " -D " $3 }
    END { printf "--target %s%s", (t == "" ? host : t), d }' "$1"
}

is_refusal() {
  awk '/^# refuse: / { found = 1 } END { exit !found }' "$1"
}

compare_all() {
  runner="$1"
  out_status=0
  for fixture in "$REPO"/bench/fixtures/macro_*.iyi; do
    if is_refusal "$fixture"; then
      "$runner" $(fixture_args "$fixture") "$fixture" > "$WORK/a.dump" 2>/dev/null || { out_status=1; continue; }
      grep -q "^error .* message=.*is refused" "$WORK/a.dump" || out_status=1
      continue
    fi
    "$runner" $(fixture_args "$fixture") "$fixture" > "$WORK/a.dump" 2>/dev/null || { out_status=1; continue; }
    "$WORK/dump_crystal" $(fixture_args "$fixture") "$fixture" > "$WORK/b.dump" 2>/dev/null || { out_status=1; continue; }
    cmp -s "$WORK/a.dump" "$WORK/b.dump" || out_status=1
  done
  return $out_status
}

fixture_count=0
refusal_count=0
total_sites=0
for fixture in "$REPO"/bench/fixtures/macro_*.iyi; do
  fixture_name="bench/fixtures/$(basename "$fixture")"
  fixture_count=$((fixture_count + 1))
  if is_refusal "$fixture"; then
    refusal_count=$((refusal_count + 1))
    "$WORK/exercise" $(fixture_args "$fixture") "$fixture" > "$WORK/iyi.dump" 2>/dev/null || true
    if grep -q "^error .* message=.*is refused" "$WORK/iyi.dump"; then
      echo "  $fixture_name: refused by name, as the port's contract says"
    else
      echo "  $fixture_name: NOT REFUSED"
      diverged=$((diverged + 1))
      status=1
    fi
    continue
  fi
  if ! "$WORK/exercise" $(fixture_args "$fixture") "$fixture" > "$WORK/iyi.dump" 2> "$WORK/iyi.err"; then
    echo "  $fixture_name: THE PORT FAILED: $(awk 'NR==1' "$WORK/iyi.err")"
    diverged=$((diverged + 1))
    status=1
    continue
  fi
  "$WORK/dump_crystal" $(fixture_args "$fixture") "$fixture" > "$WORK/crystal.dump"
  if ! cmp -s "$WORK/iyi.dump" "$WORK/crystal.dump"; then
    echo "  $fixture_name: DUMPS DIFFER"
    diff -u "$WORK/crystal.dump" "$WORK/iyi.dump" | head -30
    diverged=$((diverged + 1))
    status=1
  else
    nodes_count=$(grep -c '^site ' "$WORK/crystal.dump" || true)
    echo "  $fixture_name: identical ($nodes_count sites match the hosted compiler)"
    total_sites=$((total_sites + nodes_count))
  fi
done
echo "  Parity summary: $((fixture_count - diverged - refusal_count))/$((fixture_count - refusal_count)) comparable fixtures identical ($total_sites sites); $refusal_count refusal fixtures"

echo
echo "== 3. Mutation proofs: each one must make the comparison above fail"

# Each check rebuilds the macro engine with the mutation applied and compares its dumps
# with the hosted compiler's. It returns zero only when the comparison still passes.
check_macros_still_match() {
  "$IYI" build -o "$WORK/mut-exercise" "$REPO/bench/selfhost_macros_exercise.iyi" >/dev/null 2>&1 || return 1
  if compare_all "$WORK/mut-exercise"; then
    return 0
  fi
  return 1
}

MUTATIONS_RUN=0

prove_mutation "macro if condition truthiness inverted" "$INTERP" \
  "      if MacroMethods.truthy?(c)
        interpret(mi.then)" \
  "      if !MacroMethods.truthy?(c)
        interpret(mi.then)" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "splat argument gathering emits empty tuple" "$INTERP" \
  "@vars[macro_arg.name] = TupleLiteral.new(splat_elems)" \
  "@vars[macro_arg.name] = TupleLiteral.new([] of ASTNode)" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "macro expression output stringification suppressed" "$INTERP" \
  "val.to_s(@str)" \
  "# val.to_s(@str)" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "for loop element binding corrupts loop variable" "$INTERP" \
  "@vars[mf.vars[0].name] = firsts[i]" \
  "@vars[mf.vars[0].name] = NilLiteral.new" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "fresh variable temp name prefix altered" "$INTERP" \
  "temp_name = new_temp_var_name(\"__temp_\")" \
  "temp_name = new_temp_var_name(\"__mut_\")" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

METHODS="$REPO/src/compiler/macros/methods.iyi"
TARGET_FLAGS="$REPO/src/compiler/macros/target_flags.iyi"
prove_mutation "flag? answers from a fixed set, not the target's" "$METHODS" \
  "PlatformFlags.has_flag?(flags, name)" \
  "PlatformFlags.has_flag?([\"darwin\", \"aarch64\"], name)" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "target triple ignored when building the flag set" "$TARGET_FLAGS" \
  "Target.new(triple)" \
  "Target.new(\"x86_64-unknown-linux-gnu\")" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "-D defines dropped from the flag set" "$TARGET_FLAGS" \
  "        flags << define" \
  "        flags" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "host_flag? answers from the target's set, not the host's" "$INTERP" \
  "MacroMethods.has_flag?(MacroTargetFlags.host([] of String), flag_name_of(node))" \
  "MacroMethods.has_flag?(@flags, flag_name_of(node))" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "verbatim nesting ignores for blocks" "$PARSER" \
  "tag.starts_with?(\"for \") || tag.starts_with?(\"verbatim\")" \
  "tag.starts_with?(\"verbatim\")" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "skip_file does not stop the expansion" "$INTERP" \
  "@skipped = true" \
  "@skipped = false" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "raise message altered" "$INTERP" \
  "fail_at(node, raise_message(node.args))" \
  "fail_at(node, raise_message(node.args) + \"!\")" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "hash for loop binds the value to the key variable" "$INTERP" \
  "firsts << entries[i].key" \
  "firsts << entries[i].value" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "range for loop drops its inclusive end" "$INTERP" \
  "limit = rng.exclusive ? to_v : to_v + 1" \
  "limit = rng.exclusive ? to_v : to_v" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

prove_mutation "raise location moved to the brace" "$PARSER" \
  "exp.location = tag_loc" \
  "exp.location = open_loc" \
  -- check_macros_still_match || status=1
MUTATIONS_RUN=$((MUTATIONS_RUN + 1))

echo "  $MUTATIONS_RUN mutation proofs run"

echo
if [ "$status" -eq 0 ]; then
  echo "ALL SELFHOST MACRO EXPANSION CHECKS PASSED"
else
  echo "SELFHOST MACRO EXPANSION CHECKS FAILED"
fi
exit $status
