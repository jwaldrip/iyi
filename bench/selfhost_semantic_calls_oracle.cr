# Call-lookup oracle for bench/selfhost_semantic_calls_exercise.sh.
#
#   selfhost_semantic_calls_oracle <fixture.iyi>
#
# Builds the fixture's declarations into the hosted Program, then evaluates each
# `# call <expr>` line and prints one line:
#
#   <expr> => <matches> | none | error: <first line of the message>
#
# A call is `name(args)` (the program's own defs), or `Type.name(args)` (the
# metaclass of a type, so its class methods and the methods it inherits from
# its superclass). Arguments are literals: an integer is Int32, a string String,
# true or false Bool, and nil Nil. The lookup is the hosted `Type#lookup_matches`
# with analyze_all off, the call the hosted call pass makes first.
#
# <matches> lists each match in the hosted order, joined by "; ", as
#
#   <owner>::<name>(<restrictions>) -> <return>
#
# The owner is the type the match was found on, as the hosted context names it
# (a metaclass prints Foo.class). A restriction is the type its written form
# names, relative to the type the def was found on, or `_` when it has none.
# The return is the def's declared return type, or `needs body typing` when it
# has none. A match list that covers every argument combination ends with
# ` [cover all]`.
#
# The port's driver (bench/selfhost_semantic_calls_exercise.iyi) prints the same
# lines for the same fixtures, and the gate requires them byte-identical.
#
# Not covered here (and not written in the fixtures): named arguments, splats,
# block arguments, autocast of literals, free variables, virtual receivers, and
# `new`. Their hosted behaviour is later increments of slice S1c.
require "compiler/requires"

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
  raise "argument is not a literal: #{node.class}"
end

# The type named by a receiver written as a path, such as `Foo` or `Outer::Foo`.
def receiver_scope(program : Iyi::Program, name : String) : Iyi::Type
  found = program.lookup_path(Iyi::Path.new(name.split("::")))
  raise "unknown receiver #{name}" if found.nil?
  found.as(Iyi::Type)
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
  receiver : Iyi::Type = program
  if dot = expr.index('.')
    receiver = receiver_scope(program, expr[0...dot]).metaclass
  end
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

begin
  path = ARGV[0]? || abort("usage: selfhost_semantic_calls_oracle <fixture.iyi>")
  source = File.read(path)
  program = Iyi::Program.new
  node = Iyi::Parser.new(source).parse
  node.accept Iyi::TopLevelVisitor.new(program)
  source.each_line do |line|
    next unless line.starts_with?("# call ")
    expr = line[7..].strip
    puts "#{expr} => #{evaluate(program, expr)}"
  end
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
