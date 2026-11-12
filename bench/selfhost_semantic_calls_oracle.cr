# Call-lookup oracle for bench/selfhost_semantic_calls_exercise.sh.
#
#   selfhost_semantic_calls_oracle <fixture.iyi>
#
# Builds the fixture's declarations into the hosted Program, then evaluates each
# line of two kinds and prints one line for each:
#
#   # call <expr>   =>  <expr> => <matches> | none | error: <first line of the message>
#   # error <expr>  =>  <expr> => ok | error: <first line of the message>
#
# A call is `name(args)` (the program's own defs), `Type.name(args)` (the
# metaclass of a type: its class methods and the ones it inherits from its
# superclass), or `<receiver call>.name(args)` (an instance: the receiver call
# must have exactly one match and a declared return type, and its return is the
# receiver). Arguments are literals: an integer is Int32, a string String, true
# or false Bool, and nil Nil.
#
# A `# call` line is the hosted lookup (`Type#lookup_matches`, analyze_all off),
# the first step of the hosted call pass. Its matches are listed in the hosted
# order, joined by "; ", as
#
#   <owner>::<name>(<restrictions>) -> <return>
#
# The owner is the receiver's type, as the hosted context names it (a metaclass
# prints Foo.class). A restriction is the type its written form names, relative
# to the type the def was found on, or `_` when it has none. The return is the
# def's declared return type, or `needs body typing` when it has none. A match
# list that covers every argument combination ends with ` [cover all]`.
#
# An `# error` line runs the whole hosted compile of the fixture's declarations
# with the call as its last expression, as the compile does (the top-level pass,
# then the main pass, without a prelude), and reports the first line of the error
# it raises, or `ok`. This is where the hosted call pass writes its messages.
#
# The port's driver (bench/selfhost_semantic_calls_exercise.iyi) prints the same
# lines for the same fixtures, and the gate requires them byte-identical.
#
# Not covered here (and not written in the fixtures): named arguments, splats,
# block arguments, autocast of literals, free variables, virtual receivers, and
# `new`. Their hosted behaviour is later increments of slice S1c.
require "compiler/requires"

RECEIVER_ERROR = "receiver is not resolvable"

# The hosted compile of a source as far as the main pass, without a prelude.
class Iyi::Compiler
  def bare_pass(source : Iyi::Compiler::Source) : Nil
    program = new_program([source])
    node = program.normalize(parse(program, source))
    node, processor = program.top_level_semantic(node)
    program.semantic_after_top_level(node, processor, cleanup: false)
    nil
  end
end

# The type of a literal argument, as the hosted type of the literal.
def literal_type(program : Iyi::Program, node : Iyi::ASTNode) : Iyi::Type
  if node.is_a?(Iyi::NumberLiteral)
    return program.types["Int32"].as(Iyi::Type)
  end
  if node.is_a?(Iyi::StringLiteral)
    return program.types["String"].as(Iyi::Type)
  end
  if node.is_a?(Iyi::BoolLiteral)
    return program.types["Bool"].as(Iyi::Type)
  end
  if node.is_a?(Iyi::NilLiteral)
    return program.types["Nil"].as(Iyi::Type)
  end
  raise "argument is not a literal"
end

# The type named by a receiver written as a path, such as `Foo` or `Outer::Foo`.
def receiver_scope(program : Iyi::Program, name : String) : Iyi::Type
  found = program.lookup_path(Iyi::Path.new(name.split("::")))
  raise RECEIVER_ERROR if found.nil?
  found.as(Iyi::Type)
end

# The position of the last dot outside parentheses, or nil.
def last_dot(expr : String) : Int32?
  depth = 0
  found = nil
  expr.each_char_with_index do |c, i|
    depth += 1 if c == '('
    depth -= 1 if c == ')'
    found = i if c == '.' && depth == 0
  end
  found
end

# The type a receiver text names: a path names its metaclass, and a call names the
# instance type of its single declared return.
def receiver_type(program : Iyi::Program, text : String) : Iyi::Type
  node = Iyi::Parser.new(text).parse
  unless node.is_a?(Iyi::Call)
    return receiver_scope(program, text).metaclass
  end
  call = node.as(Iyi::Call)
  scope = call_scope(program, text)
  arg_types = call.args.map { |arg| literal_type(program, arg) }
  matches = scope.lookup_matches(Iyi::CallSignature.new(call.name, arg_types, nil, nil))
  found = matches.matches
  raise RECEIVER_ERROR if found.nil? || found.size != 1
  ret = found[0].def.return_type
  raise RECEIVER_ERROR if ret.nil?
  found[0].context.defining_type.lookup_type(ret).as(Iyi::Type)
end

# The type a call's own receiver is, for the call written as `text`.
def call_scope(program : Iyi::Program, text : String) : Iyi::Type
  if dot = last_dot(text)
    return receiver_type(program, text[0...dot])
  end
  program
end

def restriction_text(owner : Iyi::Type, restriction : Iyi::ASTNode?) : String
  return "_" if restriction.nil?
  owner.lookup_type(restriction).to_s
end

def match_text(m : Iyi::Match) : String
  scope = m.context.defining_type
  restrictions = m.def.args.map { |arg| restriction_text(scope, arg.restriction) }
  ret = m.def.return_type
  ret_text = ret.nil? ? "needs body typing" : scope.lookup_type(ret).to_s
  "#{m.context.instantiated_type.to_s}::#{m.def.name}(#{restrictions.join(", ")}) -> #{ret_text}"
end

def evaluate(program : Iyi::Program, expr : String) : String
  node = Iyi::Parser.new(expr).parse
  raise "not a call: #{expr}" unless node.is_a?(Iyi::Call)
  call = node.as(Iyi::Call)
  receiver = call_scope(program, expr)
  arg_types = call.args.map { |arg| literal_type(program, arg) }
  signature = Iyi::CallSignature.new(call.name, arg_types, nil, nil)
  matches = receiver.lookup_matches(signature)
  found = matches.matches
  return "none" if found.nil? || found.empty?
  parts = found.map { |m| match_text(m) }
  text = parts.join("; ")
  text += " [cover all]" if matches.cover_all?
  text
rescue ex : Exception
  "error: #{ex.message.to_s.lines.first? || ""}"
end

# The first line of the error the hosted compile raises for `expr` after the
# fixture's declarations, or `ok` when it raises none.
def error_text(path : String, fixture : String, expr : String) : String
  compiler = Iyi::Compiler.new
  compiler.bare_pass(Iyi::Compiler::Source.new(path, fixture + "\n" + expr + "\n"))
  "ok"
rescue ex : Exception
  "error: #{ex.message.to_s.lines.first? || ""}"
end

begin
  path = ARGV[0]? || abort("usage: selfhost_semantic_calls_oracle <fixture.iyi>")
  source = File.read(path)
  program = Iyi::Program.new
  node = Iyi::Parser.new(source).parse
  node.accept Iyi::TopLevelVisitor.new(program)
  source.each_line do |line|
    if line.starts_with?("# call ")
      expr = line[7..].strip
      puts "#{expr} => #{evaluate(program, expr)}"
    elsif line.starts_with?("# error ")
      expr = line[8..].strip
      puts "#{expr} => #{error_text(path, source, expr)}"
    end
  end
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
