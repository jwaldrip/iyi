# Declaration oracle for bench/selfhost_semantic_inline_macros_exercise.sh.
#
#   selfhost_semantic_inline_macros_oracle <file.iyi>
#
# The same analysis and dump form as bench/selfhost_semantic_declarations_oracle.cr
# (the compile's own front end, bare, with the closure of what the file imports and
# requires), with one difference. A declaration belongs to the file when its
# location is the file, and also when it was written by an inline macro the file
# holds: a macro's expansion is read from a virtual file, and the location of what it
# declares leads back, through the virtual file, to the site in the file. The
# declarations gate's oracle drops those, so it cannot measure what the top-level
# pass declares from a `{% for %}` or `{% if %}`. This oracle keeps them.
require "compiler/requires"

class Iyi::Compiler
  # iyi: the entry file as a build reads it, bare, in iyi's library.
  def declarations_program(source : Iyi::Compiler::Source) : {Program, ASTNode}
    self.prelude = "iyi/prelude"
    program = new_program([source])
    {program, parse(program, source)}
  end
end

# The file a location was written in, following every virtual file an inline macro
# expansion went through back to the site. Empty when there is none.
def origin_file(loc : Iyi::Location) : String
  origin = loc.read_from
  while origin.is_a?(Iyi::VirtualFile)
    origin = origin.expanded_location.try(&.read_from)
  end
  origin.is_a?(String) ? File.expand_path(origin) : ""
end

# Whether a declaration with these locations belongs to the entry file. With no
# entry (the built-in types) everything belongs.
def declared_in?(locations : Array(Iyi::Location)?, entry : String?) : Bool
  return true unless entry
  return false unless locations
  locations.any? { |loc| origin_file(loc) == entry }
end

def def_declared?(d : Iyi::Def, entry : String?) : Bool
  return true unless entry
  loc = d.location
  return false unless loc
  origin_file(loc) == entry
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

path = ARGV[0]? || abort("usage: selfhost_semantic_inline_macros_oracle <file.iyi>")
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
