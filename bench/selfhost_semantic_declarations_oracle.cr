# Declaration oracle for bench/selfhost_semantic_declarations_exercise.sh.
#
#   selfhost_semantic_declarations_oracle <file.iyi>
#   selfhost_semantic_declarations_oracle --initial
#
# Loads the file through the compile's own front end, bare (no prelude), together
# with the closure of what it imports and requires: each imported file is read,
# parsed and declared by the same top-level pass a build runs, with the search
# path IYI_PATH. Then it prints one text dump of the declarations the file itself
# makes: its top-level defs, then each user type with its nested types, defs and
# constants. A type or a def is printed when its location is the file, so what an
# imported file declares is not repeated here. The port's dump prints the same
# form, and the gate requires the two to agree record by record.
#
# On failure the first line of the message goes to stderr and the exit status is
# 2; the gate reports such a file as unmeasured, with that reason.
require "compiler/requires"

class Iyi::Compiler
  # iyi: the entry file as a build reads it, bare, in iyi's library (the prelude
  # name selects it, so `import std/x` is iyi's own). `parse` is private to the
  # compiler, so this reaches it from inside the class, as the typed oracle does.
  def declarations_program(source : Iyi::Compiler::Source) : {Program, ASTNode}
    self.prelude = "iyi/prelude"
    program = new_program([source])
    {program, parse(program, source)}
  end
end

# Whether a declaration with these locations belongs to the entry file. With no
# entry (the built-in types) everything belongs.
def declared_in?(locations : Array(Iyi::Location)?, entry : String?) : Bool
  return true unless entry
  return false unless locations
  locations.any? { |loc| File.expand_path(loc.filename.to_s) == entry }
end

def def_declared?(d : Iyi::Def, entry : String?) : Bool
  return true unless entry
  loc = d.location
  return false unless loc
  File.expand_path(loc.filename.to_s) == entry
end

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

def dump_type(t : Iyi::Type, io : IO, indent : String, entry : String?)
  full_name = t.is_a?(Iyi::NamedType) ? t.full_name : t.to_s
  if declared_in?(t.locations, entry)
    dump_type_header(t, full_name, io, indent, entry)
  end

  if t.is_a?(Iyi::NamedType) && !t.is_a?(Iyi::EnumType)
    t.types.keys.sort.each do |subname|
      sub = t.types[subname]
      dump_type(sub, io, "#{indent}  ", entry)
    end
  end
end

# One type's own record: its header and properties, its defs. Its nested types
# are dumped by `dump_type`, whether or not this type is the entry's.
def dump_type_header(t : Iyi::Type, full_name : String, io : IO, indent : String, entry : String?)
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

  if t.is_a?(Iyi::InstanceVarContainer)
    t.instance_vars.keys.sort.each do |ivar_name|
      io << indent << "  Ivar: " << full_name << "#" << ivar_name << "\n"
      io << indent << "    type: " << t.instance_vars[ivar_name].type.to_s << "\n"
    end
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
    all_defs = all_defs.select { |d| def_declared?(d, entry) }
    all_defs.sort_by! { |d| "#{d.receiver ? "self." : ""}#{d.name}" }
    all_defs.each do |d|
      dump_def(d, io, "#{indent}  ")
    end
  end
end

def dump_declarations(node : Iyi::ASTNode, io : IO, program : Iyi::Program, entry : String?)
  initial_types = Iyi::Program.new.types.keys.to_set
  visitor = Iyi::TopLevelVisitor.new(program)
  node.accept(visitor)
  # The hosted type declaration pass: explicit and guessed instance variables.
  Iyi::TypeDeclarationProcessor.new(program).process(node)

  if pdefs = program.defs
    top_defs = [] of Iyi::Def
    pdefs.each_value { |list| list.each { |item| top_defs << item.def } }
    top_defs = top_defs.select { |d| def_declared?(d, entry) }
    top_defs.sort_by!(&.name)
    top_defs.each do |d|
      dump_def(d, io, "")
    end
  end

  user_types = program.types.reject { |k, _| initial_types.includes?(k) }
  user_types.keys.sort.each do |name|
    dump_type(user_types[name], io, "", entry)
  end
end

# `--initial` dumps the program's own built-in types (every name a new program
# holds before any file is read), which the gate compares with the port's.
if ARGV[0]? == "--initial"
  buffer = IO::Memory.new
  initial = Iyi::Program.new
  initial.types.keys.sort.each do |name|
    dump_type(initial.types[name], buffer, "", nil)
  end
  print buffer.to_s
  exit 0
end

# The parent chain of one type, each parent on its own line, indented by depth.
def chain_show(t : Iyi::Type, depth : Int32, indent : String) : String
  line = indent + t.to_s + "\n"
  return line if depth == 0
  if t.is_a?(Iyi::ModuleType)
    t.parents.each do |p|
      line = line + chain_show(p, depth - 1, indent + "  ")
    end
  end
  line
end

# `--chain` loads the file the way the dump does, then prints the parent chain of the
# types the gate names. The prelude is loaded by the file's own require.
if ARGV[0]? == "--chain"
  chain_path = ARGV[1]? || abort("usage: selfhost_semantic_declarations_oracle --chain <file.iyi>")
  chain_entry = File.expand_path(chain_path)
  chain_compiler = Iyi::Compiler.new
  chain_program, chain_node = chain_compiler.declarations_program(Iyi::Compiler::Source.new(chain_entry, File.read(chain_entry)))
  chain_node.accept(Iyi::TopLevelVisitor.new(chain_program))
  ["Nil", "Object", "Reference", "Value", "Int32", "String", "Mine"].each do |name|
    if t = chain_program.types[name]?
      print chain_show(t, 4, "")
    else
      print "#{name} missing\n"
    end
  end
  ["Object", "Mine", "Int32"].each do |name|
    if (t = chain_program.types[name]?) && t.is_a?(Iyi::ModuleType)
      print chain_show(t.metaclass, 4, "")
    end
  end
  exit 0
end

path = ARGV[0]? || abort("usage: selfhost_semantic_declarations_oracle <file.iyi>")
entry = File.expand_path(path)
buffer = IO::Memory.new
begin
  compiler = Iyi::Compiler.new
  program, node = compiler.declarations_program(Iyi::Compiler::Source.new(entry, File.read(entry)))
  dump_declarations(node, buffer, program, entry)
rescue ex : Exception
  first_line = ex.message.to_s.lines.first? || ""
  STDERR.puts "ERROR: #{first_line}"
  exit 2
end
print buffer.to_s
