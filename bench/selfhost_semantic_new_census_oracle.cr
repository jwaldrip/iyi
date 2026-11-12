# New-call census oracle for bench/selfhost_semantic_new_census.sh.
#
#   selfhost_semantic_new_census_oracle <file.iyi>
#
# Compiles the file the way a compile builds an entry (the prelude followed by the
# file, normalized), through the hosted top-level pass and the hosted main pass, then
# prints one line per `new` call written in the file, in tree order, that the hosted
# pass typed:
#
#   site <line>:<col> call <receiver>.new(<arg types>) -> <result type> target <name>(<arg names>) targets <n>
#   site <line>:<col> call <receiver>.new(<arg types>) -> <result type> target none
#
# A call the hosted pass did not type prints nothing: it is not in the census total.
# The port's driver (bench/selfhost_semantic_new_census_exercise.iyi) prints the same
# keys for the same file. On failure the first line of the message goes to stderr and
# the exit status is 2.
require "compiler/requires"

class Iyi::Compiler
  # iyi: the compile's own sequence for an entry file (prelude, top-level pass, main
  # pass), reached from outside the class because `parse` and `new_program` are private.
  def new_census_program(source : Iyi::Compiler::Source) : {Program, ASTNode}
    program = new_program([source])
    node = parse(program, [source])
    node, processor = program.top_level_semantic(node)
    node = program.semantic_after_top_level(node, processor, cleanup: false)
    {program, node}
  end
end

def census_type_text(t : Iyi::Type?) : String
  return "nil" if t.nil?
  (t.is_a?(Iyi::NamedType) ? t.full_name : t.to_s).sub(/^::/, "")
end

# The receiver as both sides print it: nothing is `self`, a path is its names, any other
# expression is `expr`.
def census_receiver_text(recv : Iyi::ASTNode?) : String
  return "self" if recv.nil?
  recv.is_a?(Iyi::Path) ? recv.as(Iyi::Path).names.join("::") : "expr"
end

# Collects the `new` calls written in the entry file, in tree order.
class NewCensusWalk < Iyi::Visitor
  getter calls = [] of Iyi::Call

  def initialize(@absolute : String)
  end

  def visit_any(node)
    # A require carries the tree of the file it loaded as `expanded`, which the children
    # walk does not reach, so the walk enters it here (as bench/selfhost_typed_oracle.cr does).
    if node.is_a?(Iyi::Require)
      if expanded = node.expanded
        expanded.accept(self)
      end
    end
    if node.is_a?(Iyi::Call) && node.as(Iyi::Call).name == "new"
      if (loc = node.location) && (name = loc.filename).is_a?(String) && File.expand_path(name) == @absolute
        @calls << node.as(Iyi::Call)
      end
    end
    true
  end

  def visit(node)
    true
  end
end

path = ARGV[0]? || abort("usage: selfhost_semantic_new_census_oracle <file.iyi>")
entry = File.expand_path(path)
buffer = IO::Memory.new
begin
  compiler = Iyi::Compiler.new
  compiler.prelude = "iyi/prelude"
  compiler.no_codegen = true
  compiler.stdout = IO::Memory.new
  compiler.stderr = IO::Memory.new
  program, node = compiler.new_census_program(Iyi::Compiler::Source.new(entry, File.read(entry)))
  walk = NewCensusWalk.new(entry)
  node.accept(walk)
  walk.calls.each do |call|
    next if call.type?.nil?
    loc = call.location.not_nil!
    arg_types = call.args.map { |a| census_type_text(a.type?) }.join(", ")
    targets = call.target_defs
    if targets && (first = targets.first?)
      target_text = "target #{first.name}(#{first.args.map(&.name).join(", ")}) targets #{targets.size}"
    else
      target_text = "target none"
    end
    buffer << "site #{loc.line_number}:#{loc.column_number} call #{census_receiver_text(call.obj)}.new(#{arg_types}) -> #{census_type_text(call.type?)} #{target_text}\n"
  end
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
print buffer.to_s
