# iyi: `iyi doc` — III.8's doc verb, a renderer over data that exists.
#
# What it prints is `IyiMod.surface`: the caller's view of a module —
# exported functions and types with their doc comments, no bodies, no
# private anything. The same document `iyi mod context` grounds an edit
# with, served for one module at a time, because "what can I call here"
# is a question a person asks too.
#
#     iyi doc lib/thing.iyimod    # from an artifact, source not needed
#     iyi doc src/thing.iyi       # from source: the module is compiled
#                                 # alone, front end only, and read back
#     iyi doc String              # a type of the prelude: what a String
#                                 # can do, the prelude's own comments
#     iyi doc prelude             # the prelude's types, one line each
#
# No HTML, no site, no theme. The document is text because the consumers
# are a terminal and a model, and III.7's registry index — `Exports`
# served as data — is where anything richer belongs.
require "file_utils"

class Iyi::Command
  private def doc
    filename = options.shift?
    case
    when filename.nil? || filename == "--help" || filename == "-h"
      puts doc_usage
      exit
    when filename.ends_with?(".iyimod")
      abort! "no such file: #{filename}", :USAGE_ERROR unless File.file?(filename)
      artifact =
        begin
          IyiMod.read(filename)
        rescue ex : IyiMod::Error
          abort! ex.message.to_s, :USAGE_ERROR
        end
      IyiMod.surface artifact, STDOUT
    when filename.ends_with?(".iyi")
      abort! "no such file: #{filename}", :USAGE_ERROR unless File.file?(filename)
      doc_from_source(File.expand_path(filename))
    when filename == "prelude"
      doc_prelude_index
    when prelude_type_name?(filename)
      doc_prelude_type(filename)
    else
      abort! "expected a .iyi module, a .iyimod artifact, or a type of the prelude (`iyi doc String`)", :USAGE_ERROR
    end
  end

  # `String`, `Array`, `Hash::Entry`: a capital, then letters, digits,
  # underscores and `::`. Spelled out rather than a regex, which would put
  # libpcre on the compiler's floor (SPEC.md III.9).
  private def prelude_type_name?(name : String) : Bool
    return false unless name[0]?.try(&.ascii_uppercase?)
    name.each_char.all? { |char| char.ascii_alphanumeric? || char == '_' || char == ':' }
  end

  # The prelude's types, one line each - the kind, the name, the first
  # line of the comment - for the reader who does not know what to ask
  # `iyi doc String` about. The runtime's own machinery (`Iyi*`, the
  # `Lib*` bindings, the `__` names) is not the program's to call and is
  # left out.
  private def doc_prelude_index : Nil
    program = doc_prelude_program
    rows = [] of {String, String, String}
    program.types.each do |name, type|
      next if name.starts_with?("Iyi") || name.starts_with?("Lib") || name.starts_with?("__")
      next if type.is_a?(LibType) || type.is_a?(AliasType)
      next unless type.is_a?(ClassType) || type.is_a?(ModuleType) || type.is_a?(EnumType)
      next if type.private?
      # Declared or reopened by the prelude's own files: the compiler
      # declares `Int128` and `Regex` for every program and the prelude
      # says nothing about them, so they are not what a program has.
      next unless type.locations.try &.any? { |location| in_prelude?(location) }
      summary = type.doc.try(&.lines.first?) || ""
      kind = type.type_desc.lchop("generic ")
      shown = name
      if type.is_a?(GenericType) && !type.type_vars.empty?
        shown = "#{name}(#{type.type_vars.join(", ")})"
      end
      rows << {kind, shown, summary}
    end
    rows.sort_by! { |row| row[1] }
    width = rows.max_of { |row| row[0].size + 1 + row[1].size }
    rows.each do |kind, shown, summary|
      head = "#{kind} #{shown}"
      STDOUT << head
      unless summary.empty?
        STDOUT << " " * (width - head.size + 2) << "# " << summary
      end
      STDOUT << '\n'
    end
  end

  private def in_prelude?(location : Location) : Bool
    filename = location.filename
    filename.is_a?(String) && (filename.includes?("/src/iyi/") || filename.starts_with?("src/iyi/"))
  end

  private def doc_prelude_program : Program
    compiler = Compiler.new
    compiler.prelude = "iyi/prelude"
    compiler.no_codegen = true
    compiler.wants_doc = true
    compiler.stdout = IO::Memory.new
    compiler.stderr = IO::Memory.new
    begin
      compiler.top_level_semantic(Compiler::Source.new("doc.iyi", "")).program
    rescue ex : Iyi::Error | Iyi::CodeError
      abort! "the prelude does not compile: #{ex.message.to_s.lines.first?}", :USAGE_ERROR
    end
  end

  # A type of the prelude, the way a person or a model asks "what can a
  # String do": the prelude alone through the front end, the type looked
  # up, its public methods written the way `surface` writes a module's -
  # the header, each method's doc comment and signature, `end`. What the
  # compiler itself puts on every type (`allocate`, the primitives) is
  # left out, as the artifact leaves it out.
  private def doc_prelude_type(name : String) : Nil
    program = doc_prelude_program
    type = program.lookup_path(name.split("::"))
    unless type.is_a?(Type)
      abort! "the prelude has no type #{name}", :USAGE_ERROR
    end

    io = STDOUT
    if doc = type.doc
      doc.each_line { |line| io << "# " << line << '\n' }
    end
    io << type.type_desc.lchop("generic ") << ' ' << type
    if type.is_a?(GenericType) && !type.type_vars.empty?
      io << '(' << type.type_vars.join(", ") << ')'
    end
    if type.is_a?(ClassType) && (superclass = type.superclass) && superclass.to_s != "Reference" && superclass.to_s != "Struct" && superclass.to_s != "Object"
      io << " < " << superclass
    end
    io << '\n'

    signatures = [] of IyiMod::Signature
    [type, type.metaclass].each do |side|
      side.as?(ModuleType).try &.defs.try &.each_value do |items|
        items.each do |item|
          a_def = item.def
          next if a_def.body.is_a?(Primitive)
          next if a_def.visibility.private? || a_def.visibility.protected?
          next if a_def.name == "allocate" || a_def.name == "initialize" || a_def.name.starts_with?("__")
          signatures << IyiMod.signature(a_def, check_block: false)
        end
      end
    end
    signatures.sort_by! { |signature| {signature.receiver, signature.name} }
    signatures.each do |signature|
      io << '\n'
      signature.doc.each_line { |line| io << "  # " << line << '\n' } unless signature.doc.empty?
      io << "  " << IyiMod.render_signature(signature) << '\n'
    end
    io << "end\n"
  end

  # The module compiled alone — R-1's promise worn as a verb, the same way
  # `mod context` wears it: a synthetic entry imports the module, the
  # front end runs, and the artifact it emits is the answer.
  private def doc_from_source(filename : String) : Nil
    module_name = File.basename(filename, ".iyi")
    module_root = File.dirname(filename)

    emit_dir = File.tempname("iyi-doc", nil)
    Dir.mkdir_p(emit_dir)
    begin
      entry = File.join(emit_dir, "doc_entry.iyi")
      File.write(entry, "import #{module_name}\n")

      compiler = Compiler.new
      compiler.prelude = "iyi/prelude"
      compiler.no_codegen = true
      compiler.iyi_mod_table = Mod::Installer.table_for(module_root)
      compiler.emit_iyimod = emit_dir
      compiler.stdout = IO::Memory.new
      compiler.stderr = IO::Memory.new
      previous_path = ENV["IYI_PATH"]?
      begin
        ENV["IYI_PATH"] = ([module_root] + (previous_path ? [previous_path] : IyiPath.default_paths)).join(':')
        compiler.compile(
          Compiler::Source.new(entry, File.read(entry)),
          File.join(emit_dir, "unused"))
      rescue ex : Iyi::Error | Iyi::CodeError
        abort! "#{filename} does not compile alone: #{ex.message.to_s.lines.first?}", :USAGE_ERROR
      ensure
        previous_path ? (ENV["IYI_PATH"] = previous_path) : ENV.delete("IYI_PATH")
      end

      Dir.glob(File.join(emit_dir, "**", "*.iyimod")) do |candidate|
        begin
          artifact = IyiMod.read(candidate)
          if artifact.module_name == module_name
            IyiMod.surface artifact, STDOUT
            return
          end
        rescue IyiMod::Error
          next
        end
      end
      abort! "compiled, but no artifact carries module '#{module_name}'", :USAGE_ERROR
    ensure
      FileUtils.rm_rf(emit_dir)
    end
  end

  private def doc_usage
    <<-USAGE
    Usage: #{Command.program_name} doc FILE | TYPE

    Prints a module's exported surface with its doc comments — functions,
    types, methods, impls; no bodies, nothing private. FILE is a `.iyimod`
    artifact (read directly, source not needed) or a `.iyi` module (compiled
    alone, front end only). TYPE is a type of the prelude - `String`,
    `Array`, `Hash`, `Program` - printed the same way: what it can do, with
    the prelude's own comments; `prelude` lists them all, one line each.
    USAGE
  end
end
