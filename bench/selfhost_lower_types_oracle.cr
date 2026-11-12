# Lowering-types oracle for bench/selfhost_lower_types_exercise.sh.
#
#   selfhost_lower_types_oracle <fixture.iyi> <target triple>
#
# Declares the fixture into a hosted Program for the target, then prints one
# block per `# type: <expr>` line of the fixture. The port's driver
# (bench/selfhost_lower_types_exercise.iyi) prints the same blocks, and the gate
# requires the two outputs byte-identical.
#
# A block:
#
#   == <expr>
#   llvm_type: <type>                  the hosted llvm_type(type)
#   llvm_type(wants_size): <type>      llvm_type(type, wants_size: true)
#   llvm_struct_type: <type | ->       llvm_struct_type(type), where it applies
#   offsets: <n n ... | ->             the byte offset of each element of that struct
#   llvm_embedded_type: <type>
#   size: <bytes>                      size_of(llvm_type(type))
#   align: <bytes>                     align_of(llvm_type(type))
#   passed_by_value: <true|false>
#
# Normalisation, so the two printers agree. The hosted LLVM text form is not the
# IR's, so LLVM types are written here the way the IR writes them: void, iN,
# float, double, ptr, [N x T], { ... } and <{ ... }> for a literal struct, and
# %name for a named struct, the name quoted by the IR's own rule. A named
# struct's body is not printed: its fields are the `offsets:` line. A pointer's
# address space is not printed, because no fixture uses one.
#
# The layout is iyi's when the fixture declares `IyiRuntimeLock`, as the hosted
# `Program#iyi_object_layout?` decides it; the port's driver reads the same fact.
require "compiler/requires"

def ir_name_text(name : String) : String
  return name if name =~ /\A[A-Za-z_.$][A-Za-z0-9_.$]*\z/
  String.build do |io|
    io << '"'
    name.each_byte do |b|
      if b == 34_u8
        io << "\\\""
      elsif b == 92_u8
        io << "\\\\"
      elsif b < 32_u8 || b >= 127_u8
        io << "\\x" << b.to_s(16).rjust(2, '0')
      else
        io << b.chr
      end
    end
    io << '"'
  end
end

def llvm_text(t : LLVM::Type) : String
  kind = t.kind
  if kind.void?
    "void"
  elsif kind.integer?
    "i#{t.int_width}"
  elsif kind.float?
    "float"
  elsif kind.double?
    "double"
  elsif kind.pointer?
    "ptr"
  elsif kind.array?
    "[#{t.array_size} x #{llvm_text(t.element_type)}]"
  elsif kind.struct?
    if name = t.struct_name
      "%#{ir_name_text(name)}"
    else
      inner = t.struct_element_types.map { |e| llvm_text(e) }.join(", ")
      if t.packed_struct?
        inner.empty? ? "<{}>" : "<{ #{inner} }>"
      else
        inner.empty? ? "{}" : "{ #{inner} }"
      end
    end
  else
    raise "no text for an LLVM #{kind} type"
  end
end

# Where the hosted typer lays a type out as a struct: a class or struct with
# instance variables, a tuple, a named tuple, a static array. Primitives, nil,
# pointers, procs, enums, metaclasses and unions have no struct of their own.
def struct_applies?(type : Iyi::Type) : Bool
  return true if type.is_a?(Iyi::TupleInstanceType) || type.is_a?(Iyi::NamedTupleInstanceType)
  return true if type.is_a?(Iyi::StaticArrayInstanceType)
  type.is_a?(Iyi::NonGenericClassType) && !type.is_a?(Iyi::NilType)
end

# An LLVM function type as the IR writes it: `ret (params)`.
def llvm_function_text(t : LLVM::Type) : String
  params = t.params_types.map { |p| llvm_text(p) }
  "#{llvm_text(t.return_type)} (#{params.join(", ")})"
end

# The instance variables of a user class, in declaration order: `name:Type` (the name keeps its @), or `-`.
def ivars_text(type : Iyi::Type) : String
  return "-" unless type.is_a?(Iyi::NonGenericClassType) && !type.is_a?(Iyi::NilType)
  parts = type.all_instance_vars.map { |name, ivar| "#{name}:#{ivar.type}" }
  parts.empty? ? "-" : parts.join(" ")
end

# The `ids` mode's block: the type id and the id range the hosted LLVMId gives the type, or `-`.
def ids_block(name : String, program : Iyi::Program, type : Iyi::Type) : String
  mm = program.llvm_id.min_max_type_id(type)
  String.build do |io|
    io << "== " << name << "\n"
    if mm
      io << "type_id: " << mm[1] << "\n"
      io << "type_range: " << mm[0] << " " << mm[1] << "\n"
    else
      io << "type_id: -\n"
      io << "type_range: -\n"
    end
  end
end

# The pointer map of a user class under iyi's object layout, as `alloc`, `cap` and the scan
# offsets; the hosted type id is not printed (it is numbered differently, NEEDS.md row 16).
def layout_text(program : Iyi::Program, type : Iyi::Type) : String
  return "-" unless type.is_a?(Iyi::NonGenericClassType) && !type.is_a?(Iyi::NilType) && program.iyi_object_layout?
  row = program.gc_type_layout(type)
  scan = row.scan_offsets.map { |o| o.to_s }.join(" ")
  "alloc=#{row.alloc_size} cap=#{row.scan_cap} scan=#{scan.empty? ? "-" : scan}"
end

def block_text(name : String, program : Iyi::Program, typer : Iyi::LLVMTyper, type : Iyi::Type) : String
  String.build do |io|
    io << "== " << name << "\n"
    io << "llvm_type: " << llvm_text(typer.llvm_type(type)) << "\n"
    io << "llvm_type(wants_size): " << llvm_text(typer.llvm_type(type, wants_size: true)) << "\n"
    if struct_applies?(type)
      st = typer.llvm_struct_type(type)
      io << "llvm_struct_type: " << llvm_text(st) << "\n"
      if st.kind.struct?
        offsets = (0...st.struct_element_types.size).map { |i| typer.offset_of(st, i).to_s }
        io << "offsets: " << (offsets.empty? ? "-" : offsets.join(" ")) << "\n"
      else
        io << "offsets: -\n"
      end
    else
      io << "llvm_struct_type: -\n"
      io << "offsets: -\n"
    end
    io << "llvm_embedded_type: " << llvm_text(typer.llvm_embedded_type(type)) << "\n"
    io << "size: " << typer.size_of(typer.llvm_type(type)) << "\n"
    io << "align: " << typer.align_of(typer.llvm_type(type)) << "\n"
    io << "passed_by_value: " << (type.passed_by_value? ? "true" : "false") << "\n"
    io << "ivars: " << ivars_text(type) << "\n"
    io << "layout: " << layout_text(program, type) << "\n"
    io << "passed_indirectly: " << (typer.passed_indirectly?(type) ? "true" : "false") << "\n"
    if type.is_a?(Iyi::ProcInstanceType)
      io << "proc_function: " << llvm_function_text(typer.proc_type(type)) << "\n"
      io << "closure_function: " << llvm_function_text(typer.closure_type(type)) << "\n"
    end
  end
end

# Splits operands at the commas outside every parenthesis.
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

# Splits at a separator character outside every parenthesis, trimmed, keeping empty parts.
def split_outside(text : String, sep : Char) : Array(String)
  parts = [] of String
  depth = 0
  current = String::Builder.new
  text.each_char do |c|
    if c == sep && depth == 0
      parts << current.to_s.strip
      current = String::Builder.new
      next
    end
    depth += 1 if c == '('
    depth -= 1 if c == ')'
    current << c
  end
  parts << current.to_s.strip
  parts
end

# The hosted type a written type names: `Int32`, `Color`, `Pointer(Int32)`, `Color.class`.
def resolve(program : Iyi::Program, name : String) : Iyi::Type
  name = name.strip
  # A union is its members merged, `A | B`, and a nilable type is the type merged with Nil, `A?`.
  bars = split_outside(name, '|')
  if bars.size > 1
    members = bars.map { |b| resolve(program, b).as(Iyi::Type?) }
    return program.type_merge(members).as(Iyi::Type)
  end
  if name.ends_with?("?") && name.size > 1
    inner = resolve(program, name[0...-1]).as(Iyi::Type?)
    return program.type_merge([inner, resolve(program, "Nil").as(Iyi::Type?)]).as(Iyi::Type)
  end
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

begin
  path = ARGV[0]? || abort("usage: selfhost_lower_types_oracle <fixture.iyi> <target triple>")
  triple = ARGV[1]? || abort("usage: selfhost_lower_types_oracle <fixture.iyi> <target triple>")
  source = File.read(path)
  program = Iyi::Program.new
  program.codegen_target = Iyi::Codegen::Target.new(triple)
  node = Iyi::Parser.new(source).parse
  # The hosted declaration passes: top-level declarations, then the instance variable
  # declarations and the types guessed from assignments (program.cr top_level_semantic).
  program.top_level_semantic(node)
  typer = program.llvm_typer
  mode = ARGV[2]? || "blocks"
  source.each_line do |line|
    next unless line.starts_with?("# type: ")
    expr = line[8..].strip
    if mode == "ids"
      puts ids_block(expr, program, resolve(program, expr))
    else
      puts block_text(expr, program, typer, resolve(program, expr))
    end
  end
rescue ex : Exception
  STDERR.puts "ERROR: #{ex.message.to_s.lines.first? || ""}"
  exit 2
end
