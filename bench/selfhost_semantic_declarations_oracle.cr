# Declaration oracle for bench/selfhost_semantic_declarations_exercise.sh.
#
#   selfhost_semantic_declarations_oracle <file.iyi>
#
# Analyses the file alone, with no prelude, through the hosted top-level pass
# (Iyi::TopLevelVisitor over a fresh Iyi::Program), and prints one text dump of
# every declaration the file makes: its top-level defs, then each user type with
# its nested types, defs and constants. The port's dump_program_declarations
# prints the same form, and the gate requires the two to agree record by record.
#
# On failure the first line of the message goes to stderr and the exit status
# is 2; the gate reports such a file as unmeasured, with that reason.
require "compiler/requires"

def dump_def(d : Iyi::Def, io : IO, indent : String)
  io << indent << "Def: " << (d.receiver ? "self." : "") << d.name << "\n"
  vis_str = case d.visibility
            when .private? then "private"
            else                "public"
            end
  io << indent << "  visibility: " << vis_str << "\n"
  if d.is_a?(Iyi::External)
    io << indent << "  real_name: " << d.real_name << "\n"
    io << indent << "  varargs: " << d.varargs? << "\n"
  end
  io << indent << "  abstract: " << d.abstract? << "\n"
  args_strs = d.args.map do |arg|
    s = arg.name
    s += " : #{arg.restriction}" if arg.restriction
    s += " = #{arg.default_value}" if arg.default_value
    s
  end
  io << indent << "  args: [" << args_strs.join(", ") << "]\n"
  ret_str = d.return_type ? d.return_type.to_s : "nil"
  ret_str = ret_str.sub(/^::/, "")
  io << indent << "  return_type: " << ret_str << "\n"
end

def dump_type(t : Iyi::Type, io : IO, indent : String)
  full_name = t.is_a?(Iyi::NamedType) ? t.full_name : t.to_s
  kind = case t
         when Iyi::EnumType   then "enum"
         when Iyi::TraitType  then "trait"
         when Iyi::ClassType  then t.struct? ? "struct" : "class"
         when Iyi::LibType    then "lib"
         when Iyi::ModuleType then "module"
         when Iyi::AliasType  then "alias"
         when Iyi::Const      then "constant"
         else                      "type"
         end
  io << indent << "Type: " << full_name << " (" << kind << ")\n"
  vis_str = (t.is_a?(Iyi::NamedType) && t.private?) ? "private" : "public"
  io << indent << "  visibility: " << vis_str << "\n"
  io << indent << "  abstract: " << t.abstract? << "\n"

  if t.is_a?(Iyi::GenericType)
    io << indent << "  type_vars: [" << t.type_vars.join(", ") << "]\n"
  end

  if t.is_a?(Iyi::ClassType) && (sc = t.superclass)
    io << indent << "  superclass: " << sc.to_s << "\n"
  end

  if t.is_a?(Iyi::ModuleType) && !t.parents.empty?
    io << indent << "  parents: [" << t.parents.map(&.to_s).sort.join(", ") << "]\n"
  end

  if t.is_a?(Iyi::TraitType)
    if t.is_a?(Iyi::TraitSupertraits) && (st = t.supertraits) && !st.empty?
      io << indent << "  supertraits: [" << st.map(&.to_s).sort.join(", ") << "]\n"
    end
    if t.is_a?(Iyi::GenericTraitType) && !t.assoc_types.empty?
      io << indent << "  assoc_types: [" << t.assoc_types.sort.join(", ") << "]\n"
    end
  end

  if t.is_a?(Iyi::EnumType)
    members = t.types.map do |k, v|
      val_s = v.as(Iyi::Const).value.to_s
      val_s = val_s.split('_').first if val_s.includes?('_')
      "#{k}=#{val_s}"
    end.sort
    io << indent << "  enum_members: [" << members.join(", ") << "]\n"
  end

  if t.is_a?(Iyi::AliasType)
    t.process_value
    io << indent << "  aliased_type: " << t.aliased_type.to_s << "\n"
  end

  if t.is_a?(Iyi::Const)
    io << indent << "  const_value: " << t.value.to_s << "\n"
  end

  if t.is_a?(Iyi::ModuleType)
    all_defs = [] of Iyi::Def
    t.defs.try &.each_value { |list| list.each { |item| all_defs << item.def } }
    if (meta = t.metaclass) && meta.is_a?(Iyi::ModuleType) && !meta.same?(t)
      meta.defs.try &.each_value do |list|
        list.each do |item|
          next if item.def.name == "allocate"
          next if item.def.name == "new" && t.is_a?(Iyi::EnumType)
          all_defs << item.def
        end
      end
    end
    all_defs.sort_by! { |d| "#{d.receiver ? "self." : ""}#{d.name}" }
    all_defs.each do |d|
      dump_def(d, io, "#{indent}  ")
    end
  end

  if t.is_a?(Iyi::NamedType) && !t.is_a?(Iyi::EnumType)
    t.types.keys.sort.each do |subname|
      sub = t.types[subname]
      dump_type(sub, io, "#{indent}  ")
    end
  end
end

def dump_declarations(node : Iyi::ASTNode, io : IO)
  program = Iyi::Program.new
  initial_types = program.types.keys.to_set
  visitor = Iyi::TopLevelVisitor.new(program)
  node.accept(visitor)

  if pdefs = program.defs
    top_defs = [] of Iyi::Def
    pdefs.each_value { |list| list.each { |item| top_defs << item.def } }
    top_defs.sort_by!(&.name)
    top_defs.each do |d|
      dump_def(d, io, "")
    end
  end

  user_types = program.types.reject { |k, _| initial_types.includes?(k) }
  user_types.keys.sort.each do |name|
    dump_type(user_types[name], io, "")
  end
end

# `--initial` dumps the program's own built-in types (every name a new program
# holds before any file is read), which the gate compares with the port's.
if ARGV[0]? == "--initial"
  buffer = IO::Memory.new
  initial = Iyi::Program.new
  initial.types.keys.sort.each do |name|
    dump_type(initial.types[name], buffer, "")
  end
  print buffer.to_s
  exit 0
end

path = ARGV[0]? || abort("usage: selfhost_semantic_declarations_oracle <file.iyi>")
buffer = IO::Memory.new
begin
  src = File.read(path)
  parser = Iyi::Parser.new(src)
  parser.filename = path
  node = parser.parse
  dump_declarations(node, buffer)
rescue ex : Exception
  first_line = ex.message.to_s.lines.first? || ""
  STDERR.puts "ERROR: #{first_line}"
  exit 2
end
print buffer.to_s
