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
# Type names in an operation may be written with arguments: `Box(Int32)`,
# `Pair(Int32, String)`, `Proc(Int32, Int32)` (the last argument is the return
# type). Commas inside parentheses do not separate operands.
#
# Operations:
#   T.<member>                     the receiver is a type name, or `T.class` for
#                                  its metaclass, or a generic instance. Members:
#     nil_type? pointer? proc? void? no_return? virtual? metaclass?
#     virtual_metaclass? struct? reference_like? leaf? subclasses
#     all_subclasses instance_type virtual_type splat_index proc? remove_alias
#   merge(A, B) merge(A, B, C)     Program#type_merge (types/merge.iyi)
#   intersect(T, U)                Type.common_descendent (types/intersect.iyi)
#   filter(T, kind[, args])        a type filter applied to T (types/filters.iyi):
#     is_a, U | nil? | not_is_a, U | not_nil? | truthy | not_truthy |
#     responds_to, name | or_is_a, U, V | and_is_a, U, V
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

# Splits operands at the commas that are outside every parenthesis.
def split_top(text : String) : Array(String)
  parts = [] of String
  depth = 0
  current = String::Builder.new
  text.each_char do |c|
    if c == ',' && depth == 0
      parts << current.to_s.strip
      current = String::Builder.new
      next
    end
    depth += 1 if c == '('
    depth -= 1 if c == ')'
    current << c
  end
  last = current.to_s.strip
  parts << last unless last.empty?
  parts
end

def resolve(program : Iyi::Program, name : String) : Iyi::Type
  name = name.strip
  if name.ends_with?(".class")
    return resolve(program, name[0...-6]).metaclass
  end
  if open = name.index('(')
    raise "unknown generic #{name}" unless name.ends_with?(")")
    base_name = name[0...open]
    args = split_top(name[(open + 1)...-1]).map { |arg| resolve(program, arg) }
    if base_name == "Proc"
      return program.proc_of(args)
    end
    base = resolve(program, base_name)
    unless base.is_a?(Iyi::GenericClassType)
      raise "#{base_name} takes no type arguments"
    end
    return base.as(Iyi::GenericClassType).instantiate(args.map { |arg| arg.as(Iyi::TypeVar) })
  end
  t = program.types[name]?
  raise "unknown type #{name}" if t.nil?
  t
end

def evaluate_merge(program : Iyi::Program, op : String) : String
  parts = split_top(op[6...-1])
  case parts.size
  when 2
    type_text(program.type_merge(resolve(program, parts[0]), resolve(program, parts[1])))
  when 3
    type_text(program.type_merge([resolve(program, parts[0]), resolve(program, parts[1]), resolve(program, parts[2])] of Iyi::Type?))
  else
    raise "merge takes two or three types: #{op}"
  end
end

def evaluate_intersect(program : Iyi::Program, op : String) : String
  parts = split_top(op[10...-1])
  raise "intersect takes two types: #{op}" unless parts.size == 2
  type_text(Iyi::Type.common_descendent(resolve(program, parts[0]), resolve(program, parts[1])))
end

def evaluate_filter(program : Iyi::Program, op : String) : String
  parts = split_top(op[7...-1])
  t = resolve(program, parts[0])
  nil_t = resolve(program, "Nil")
  filter = case parts[1]
           when "is_a"        then Iyi::SimpleTypeFilter.new(resolve(program, parts[2]))
           when "nil?"        then Iyi::SimpleTypeFilter.new(nil_t)
           when "not_is_a"    then Iyi::SimpleTypeFilter.new(resolve(program, parts[2])).not
           when "not_nil?"    then Iyi::SimpleTypeFilter.new(nil_t).not
           when "truthy"      then Iyi::TruthyFilter.instance
           when "not_truthy"  then Iyi::TruthyFilter.instance.not
           when "responds_to" then Iyi::RespondsToTypeFilter.new(parts[2])
           when "or_is_a"
             Iyi::OrTypeFilter.new(Iyi::SimpleTypeFilter.new(resolve(program, parts[2])), Iyi::SimpleTypeFilter.new(resolve(program, parts[3])))
           when "and_is_a"
             Iyi::AndTypeFilter.new(Iyi::SimpleTypeFilter.new(resolve(program, parts[2])), Iyi::SimpleTypeFilter.new(resolve(program, parts[3])))
           else raise "unknown filter #{parts[1]}"
           end
  type_text(filter.apply(t))
end

def evaluate(program : Iyi::Program, op : String) : String
  return evaluate_merge(program, op) if op.starts_with?("merge(")
  return evaluate_intersect(program, op) if op.starts_with?("intersect(")
  return evaluate_filter(program, op) if op.starts_with?("filter(")
  # The receiver may carry arguments, so the member starts after the last
  # dot that is outside parentheses.
  dot = nil
  depth = 0
  op.each_char_with_index do |c, i|
    depth += 1 if c == '('
    depth -= 1 if c == ')'
    dot = i if c == '.' && depth == 0
  end
  raise "malformed operation #{op}" if dot.nil?
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
  when "remove_alias"       then type_text(t.remove_alias)
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
