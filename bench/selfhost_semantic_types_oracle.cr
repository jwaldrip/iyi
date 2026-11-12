# Type-model oracle for bench/selfhost_semantic_types_exercise.sh.
#
#   selfhost_semantic_types_oracle <fixture.iyi>
#
# Builds the fixture's declarations into the hosted Program, then evaluates each
# operation line of the form `# op <op>` in the fixture and prints one line:
#
#   <op> => <result>
#
# Results use the hosted type's to_s form. Booleans print as true or false, a
# list of types as [A, B], an absent type as nil, and an integer as its digits.
# The port's driver (bench/selfhost_semantic_types_exercise.iyi) prints the same
# lines for the same fixtures, and the gate requires them byte-identical.
#
# Operations (the receiver is a type name, with no dot in it, then one member):
#   T.nil_type? T.pointer? T.proc? T.void? T.no_return? T.virtual? T.metaclass?
#   T.virtual_metaclass? T.struct? T.reference_like? T.leaf?
#   T.subclasses T.all_subclasses T.instance_type T.virtual_type T.splat_index
require "compiler/requires"

def type_text(t : Iyi::Type?) : String
  return "nil" if t.nil?
  t.to_s
end

def bool_text(b : Bool) : String
  b ? "true" : "false"
end

def list_text(types : Array(Iyi::Type)) : String
  "[#{types.map { |t| type_text(t) }.join(", ")}]"
end

def resolve(program : Iyi::Program, name : String) : Iyi::Type
  t = program.types[name]?
  raise "unknown type #{name}" if t.nil?
  t
end

def evaluate(program : Iyi::Program, op : String) : String
  dot = op.index('.') || raise "malformed operation #{op}"
  t = resolve(program, op[0...dot])
  member = op[(dot + 1)..]
  case member
  when "nil_type?"          then bool_text(t.nil_type?)
  when "pointer?"           then bool_text(t.pointer?)
  when "proc?"              then bool_text(t.proc?)
  when "void?"              then bool_text(t.void?)
  when "no_return?"         then bool_text(t.no_return?)
  when "virtual?"           then bool_text(t.virtual?)
  when "metaclass?"         then bool_text(t.metaclass?)
  when "virtual_metaclass?" then bool_text(t.virtual_metaclass?)
  when "leaf?"              then bool_text(t.leaf?)
  when "struct?"            then bool_text(t.struct?)
  when "reference_like?"    then bool_text(t.reference_like?)
  when "subclasses"         then list_text(t.subclasses)
  when "all_subclasses"     then list_text(t.all_subclasses)
  when "instance_type"      then type_text(t.instance_type)
  when "virtual_type"       then type_text(t.virtual_type)
  when "splat_index"
    idx = t.splat_index
    idx.nil? ? "nil" : idx.to_s
  else
    raise "unknown operation #{member}"
  end
end

begin
  path = ARGV[0]? || abort("usage: selfhost_semantic_types_oracle <fixture.iyi>")
  source = File.read(path)
  program = Iyi::Program.new
  node = Iyi::Parser.new(source).parse
  node.accept Iyi::TopLevelVisitor.new(program)
  source.each_line do |line|
    next unless line.starts_with?("# op ")
    op = line[5..].strip
    puts "#{op} => #{evaluate(program, op)}"
  end
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
