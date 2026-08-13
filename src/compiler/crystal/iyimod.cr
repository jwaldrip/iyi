require "./config"

# iyi: `.iyimod`, the module artifact — SPEC.md Part IV.
#
# The contract: to compile module B which imports A, the compiler reads A's
# `.iyimod` and never opens A's source. Everything R-1 rests on is this file,
# and so is the measured win — the top-level pass costs 0.99 s today and 0.004 s
# when the prelude arrives pre-analysed (IV.1a).
#
# ## Shape
#
# A container with a section table, so a reader can take the sections it needs
# and seek past the rest. That is not tidiness: a consumer wants `Exports` and
# emphatically does not want to page in `ObjectCode` to get it, and the table is
# what makes skipping possible without parsing.
#
#     magic          "IYIMOD\0\0"
#     format version u32
#     section count  u32
#     section table  { kind u16, padding u16, length u32 } * count
#     payloads       in table order
#
# Binary, for read speed (IV.1). Little-endian throughout, because the format is
# not portable between targets anyway — the header records a target triple and a
# reader rejects a mismatch.
#
# ## What is not here yet
#
# `Hashes`, `MacroBodies`, `MonoBodies` and `ObjectCode` are named in `Section`
# and not written. The kinds are declared now so that a file written today is
# readable by the compiler that adds them: an unknown section is skipped, a
# known one that is absent is simply absent.
module Crystal::IyiMod
  MAGIC = "IYIMOD\0\0".to_slice

  # Bumped when the layout of any section changes incompatibly. IV.5: a
  # `.iyimod` from another version is rejected and rebuilt, never migrated.
  FORMAT_VERSION = 5_u32

  FORMAT = IO::ByteFormat::LittleEndian

  enum Section : UInt16
    Header      = 1
    Hashes      = 2
    Imports     = 3
    Exports     = 4
    MacroBodies = 5
    MonoBodies  = 6
    ObjectCode  = 7
  end

  class Error < Crystal::Error
  end

  # The value the `compiler_version` field is compared against.
  #
  # Compact and exact, because IV.5 makes it an equality test rather than a
  # range: an artifact from another compiler is rejected and rebuilt, never
  # migrated. The build commit is in it for the same reason the daemon refuses
  # a client built from a different one — two compilers that agree on their
  # release number can still disagree about everything else.
  def self.compiler_version : String
    if commit = Config.build_commit
      "#{Config.version}+#{commit}"
    else
      Config.version
    end
  end

  # One exported function's signature — a `pub def` (R-2).
  #
  # Types are carried as the **source text of the annotation the author wrote**,
  # not as a rendering of the inferred `Crystal::Type`. R-2 is what makes that
  # sound: everything a module exports carries full parameter and return types,
  # so the annotation *is* the signature and there is nothing to infer. It is
  # also the more robust choice — the reader parses it with the same parser that
  # read the source, instead of a second grammar invented for this file.
  #
  # An empty *return_type* means none was written. A constructor is the ordinary
  # case — its result is its type and nobody annotates it — so this is recorded
  # as absent rather than filled in with a type the author never wrote.
  #
  # A parameter is one whole parameter as written — `name : Type = default`,
  # `*rest : T`, `to target : T`. Splitting it into a name and a type lost the
  # rest, and the rest is not decoration: a default value changes the arity a
  # consumer sees, and dropping it makes calls that compile against the source
  # fail against the artifact.
  #
  # *block_parameter* is `& : Elem -> Bool` and empty when there is none. It is
  # here because a consumer cannot type a block without it. With the body gone
  # there is no `yield` left to infer from, so the annotation is the only thing
  # that says what the block receives and returns — which is R-2 reaching a
  # place it was not obviously about.
  #
  # *free_variables* is `forall U`, without which a return type naming `U` does
  # not resolve on the far side. *required* is `abstract def`: a requirement an
  # impl has to satisfy (II.6) rather than something a consumer may call.
  record Signature,
    name : String,
    receiver : String,
    parameters : Array(String),
    block_parameter : String,
    return_type : String,
    free_variables : Array(String),
    required : Bool

  # An exported type: `pub struct`, `pub class`, `pub trait`, `pub enum`.
  #
  # For a trait, *methods* is what the trait requires and supplies — II.6's
  # abstract requirements and the signatures (not bodies) of its defaults,
  # which is what a consumer needs to check an impl against. For a struct or
  # class it is the exported methods declared on it.
  #
  # *assoc_types* is kept apart from *type_parameters* because II.6 keeps them
  # apart: a parameter is chosen by whoever implements the trait and an
  # associated type is answered by the impl. Both are type variables of the
  # same type internally, so a reader that merged them would ask an impl of
  # `Enumerable` to supply `Elem` at the `impl` line, which is the one place
  # II.6 says it does not go.
  record TypeDecl,
    name : String,
    kind : String,
    type_parameters : Array(String),
    assoc_types : Array(String),
    supertraits : Array(String),
    methods : Array(Signature)

  # One `(Trait, Type)` pair this module provides.
  #
  # This is the record II.4 depends on: it lets a consumer answer "does
  # `Customer` implement `ToJSON`?" without reading `Customer`. R-3 is what
  # makes the answer complete rather than merely available — an impl may only
  # live in the trait's module or the type's module, so the pairs are always
  # findable from one of two files a consumer already has, and IV.4's argument
  # that no two modules can define the same impl rests on the same rule.
  #
  # The pair alone says the impl exists; the rest is what it takes to state it
  # again on the far side. `impl Enumerable for List(T) forall T` answering
  # `type Elem = T` is four separate things — a trait, a target, the impl's own
  # parameters, and the answers — and an artifact that carried only the first
  # two would leave a consumer knowing `List` enumerates something without
  # knowing what.
  record ImplRecord,
    trait_name : String,
    type_name : String,
    trait_arguments : Array(String),
    free_variables : Array(String),
    free_variable_bounds : Array({String, String}),
    assoc_types : Array({String, String})

  # What a module offers another module: `Exports` in IV.1's table.
  #
  # Deliberately not everything the module contains. Bodies of ordinary `pub`
  # functions stay out, and so does everything unexported, because a consumer
  # that could reach them would come to depend on an implementation detail —
  # and because a name left unmarked has to be *unreachable*, or these
  # metadata would not be enough to compile against (IV.2).
  #
  # ## What is not here yet
  #
  # Layout templates, type descriptors, field lists and constants. The first
  # three are what codegen needs rather than what the front end needs, so they
  # arrive with object code; a consumer can typecheck a call against a
  # signature without knowing how the receiver is laid out.
  record Exports,
    functions : Array(Signature),
    types : Array(TypeDecl),
    impls : Array(ImplRecord) do
    def self.empty
      new([] of Signature, [] of TypeDecl, [] of ImplRecord)
    end

    def empty?
      functions.empty? && types.empty? && impls.empty?
    end
  end

  # What a `.iyimod` says about the module it was built from.
  #
  # Only the parts the compiler can already produce. This grows a field at a
  # time as the sections above are filled in, and each addition is a format
  # version bump rather than an optional field, because a half-understood
  # artifact is the failure mode IV.1 exists to avoid.
  class Artifact
    # The module path as written in `module a/b`, e.g. `app/greeter`.
    getter module_name : String

    # Absolute path of the source this was built from. Diagnostic only — a
    # consumer must never need it, since needing it is the thing R-1 forbids.
    getter source_path : String

    # The compiler that wrote it. IV.5: must match exactly.
    getter compiler_version : String

    getter target_triple : String

    # The build flags that were in effect, sorted. A prelude analysed under one
    # set of flags cannot be adopted by a build under another (see the daemon's
    # `prelude_cache_key`), and the same is true here: macros branch on flags.
    getter flags : Array(String)

    # The module paths this module imports, in the order the DAG edges were
    # recorded. III.5's initialisation order is derivable from these.
    getter imports : Array(String)

    # What another module may reach. See `Exports`.
    getter exports : Exports

    def initialize(@module_name, @source_path, @compiler_version, @target_triple,
                   @flags, @imports, @exports = Exports.empty)
    end
  end

  # Writes *artifact* to *path*, atomically.
  #
  # Atomic because a half-written artifact that a later build reads as valid is
  # the worst failure a build cache has: it is wrong, it is cached, and nothing
  # about it looks broken. Written to a sibling temporary and renamed, so a
  # reader sees either the old file or the new one.
  def self.write(artifact : Artifact, path : String) : Nil
    sections = [] of {Section, Bytes}
    sections << {Section::Header, encode_header(artifact)}
    sections << {Section::Imports, encode_imports(artifact)}
    sections << {Section::Exports, encode_exports(artifact)}

    Dir.mkdir_p(File.dirname(path))
    temporary = "#{path}.#{Process.pid}.tmp"
    begin
      File.open(temporary, "wb") do |file|
        file.write MAGIC
        file.write_bytes FORMAT_VERSION, FORMAT
        file.write_bytes sections.size.to_u32, FORMAT
        sections.each do |(kind, payload)|
          file.write_bytes kind.value, FORMAT
          file.write_bytes 0_u16, FORMAT # padding, keeps entries 8-byte aligned
          file.write_bytes payload.size.to_u32, FORMAT
        end
        sections.each { |(_, payload)| file.write payload }
      end
      File.rename temporary, path
    rescue ex
      File.delete?(temporary)
      raise ex
    end
  end

  # Reads the artifact at *path*.
  #
  # Rejects rather than migrates: a file from another format or compiler version
  # is an error the caller answers by rebuilding it (IV.5).
  def self.read(path : String) : Artifact
    File.open(path, "rb") do |file|
      magic = Bytes.new(MAGIC.size)
      file.read_fully?(magic) || raise Error.new("#{path} is too short to be a .iyimod")
      raise Error.new("#{path} is not a .iyimod") unless magic == MAGIC

      format_version = file.read_bytes(UInt32, FORMAT)
      unless format_version == FORMAT_VERSION
        raise Error.new("#{path} is .iyimod format v#{format_version}, this compiler writes v#{FORMAT_VERSION}")
      end

      count = file.read_bytes(UInt32, FORMAT)
      table = Array({UInt16, UInt32}).new(count) do
        kind = file.read_bytes(UInt16, FORMAT)
        file.read_bytes(UInt16, FORMAT)
        {kind, file.read_bytes(UInt32, FORMAT)}
      end

      header = nil
      imports = [] of String
      exports = Exports.empty

      table.each do |(kind, length)|
        payload = Bytes.new(length)
        file.read_fully?(payload) || raise Error.new("#{path} ends inside a section")
        case Section.from_value?(kind)
        when Section::Header  then header = decode_header(payload)
        when Section::Imports then imports = decode_imports(payload)
        when Section::Exports then exports = decode_exports(payload)
        else
          # Written by a later compiler, or a section this one does not need.
          # Skipping is the point of the table.
        end
      end

      unless header
        raise Error.new("#{path} has no header section")
      end

      Artifact.new(header[:module_name], header[:source_path], header[:compiler_version],
        header[:target_triple], header[:flags], imports, exports)
    end
  end

  # Text for `crystal mod dump` — under the eventual `iyi` binary this is
  # `iyi mod dump`, which IV.1 requires rather than merely suggests: a cache
  # format nobody can read is a cache format nobody can debug.
  def self.dump(artifact : Artifact, io : IO) : Nil
    io.puts "module        #{artifact.module_name}"
    io.puts "source        #{artifact.source_path}"
    io.puts "compiler      #{artifact.compiler_version}"
    io.puts "target        #{artifact.target_triple}"
    io.puts "flags         #{artifact.flags.empty? ? "(none)" : artifact.flags.join(", ")}"
    if artifact.imports.empty?
      io.puts "imports       (none)"
    else
      io.puts "imports"
      artifact.imports.each { |name| io.puts "  #{name}" }
    end

    exports = artifact.exports
    if exports.empty?
      io.puts "exports       (none)"
    else
      io.puts "exports"
      exports.functions.each { |signature| io.puts "  #{render_signature(signature)}" }

      exports.types.each do |declaration|
        io.puts "  #{render_type_header(declaration)}"
        declaration.assoc_types.each { |name| io.puts "    type #{name}" }
        declaration.methods.each { |signature| io.puts "    #{render_signature(signature)}" }
      end

      exports.impls.each do |record|
        io.puts "  #{render_impl_header(record)}"
        record.assoc_types.each { |(name, answer)| io.puts "    type #{name} = #{answer}" }
      end
    end

    # Said out loud on every dump. What is missing is no longer whole
    # declarations but the parts of them codegen needs, and a reader has no way
    # to tell a field list that is absent from one that is empty.
    io.puts
    io.puts "note          format v#{FORMAT_VERSION} carries declarations and"
    io.puts "              signatures. Field lists, layout templates, type"
    io.puts "              descriptors and constants are not in this file yet"
    io.puts "              (SPEC.md IV.2)."
  end

  # The artifact as the iyi declarations it was built from.
  #
  # This is the whole point of the file: `import` reads it and compiles against
  # this text instead of opening the module's source (R-1). It is iyi source
  # rather than an AST because the signatures already are source — the parser
  # that read the module is the one that should read its declarations back, and
  # a second grammar for this file would be a second thing to keep correct.
  #
  # Bodies are absent rather than empty. Every `def` here is a header, and a
  # call against it is typed from its return annotation, which R-2 guarantees
  # is written. That is also the boundary: this is enough to typecheck against
  # and not enough to generate code from, which is why a build that reads
  # artifacts is a front-end-only build until `ObjectCode` exists (IV.1a).
  #
  # Everything is `pub`, because everything in the file is: an unexported name
  # never reached `Exports`, and R-2b needs it to stay unreachable rather than
  # merely unmentioned.
  def self.declarations(artifact : Artifact, io : IO) : Nil
    io << "module " << artifact.module_name << '\n'

    exports = artifact.exports
    exports.functions.each do |signature|
      io << '\n'
      render_declaration io, signature, exported: true
    end

    exports.types.each do |declaration|
      io << "\npub " << render_type_header(declaration) << '\n'
      declaration.assoc_types.each { |name| io << "  type " << name << '\n' }
      declaration.methods.each do |signature|
        render_declaration io, signature, indent: "  "
      end
      io << "end\n"
    end

    # After the types, because an impl needs its target declared and because
    # the requirement check reads the methods off the target rather than out of
    # the impl's body — which is what lets that body be empty here.
    exports.impls.each do |record|
      io << '\n' << render_impl_header(record) << '\n'
      record.assoc_types.each { |(name, answer)| io << "  type " << name << " = " << answer << '\n' }
      io << "end\n"
    end
  end

  private def self.render_declaration(io : IO, signature : Signature,
                                      exported = false, indent = "") : Nil
    io << indent
    io << "pub " if exported
    io << render_signature(signature) << '\n'
    # An `abstract def` ends at its signature. Anything else needs the `end`
    # its absent body would have carried.
    io << indent << "end\n" unless signature.required
  end

  # A type's declaration line — `struct List(T)`, `trait Ord : Eq`.
  #
  # The kind loses its `generic ` prefix, which is how a `Crystal::Type`
  # describes itself and not how anybody declares one: what makes `List`
  # generic is the `(T)` this line already carries.
  def self.render_type_header(declaration : TypeDecl) : String
    String.build do |io|
      io << declaration.kind.lchop("generic ") << ' ' << declaration.name

      parameters = declaration.type_parameters
      unless parameters.empty?
        io << '('
        parameters.join(io, ", ")
        io << ')'
      end

      supertraits = declaration.supertraits
      unless supertraits.empty?
        io << " : "
        supertraits.join(io, ", ")
      end
    end
  end

  # An impl's declaration line — `impl Enumerable for List(T) forall T`.
  def self.render_impl_header(record : ImplRecord) : String
    String.build do |io|
      io << "impl " << record.trait_name

      arguments = record.trait_arguments
      unless arguments.empty?
        io << '('
        arguments.join(io, ", ")
        io << ')'
      end

      io << " for " << record.type_name

      free_variables = record.free_variables
      unless free_variables.empty?
        bounds = record.free_variable_bounds.to_h
        io << " forall "
        free_variables.join(io, ", ") do |name, inner|
          inner << name
          if bound = bounds[name]?
            inner << " : " << bound
          end
        end
      end
    end
  end

  # One signature as the declaration it came from.
  #
  # `mod dump` prints this, and so does the reconstruction a consumer compiles
  # against — deliberately the same text from the same function. A dump that
  # showed something other than what the compiler reads would be a debugging
  # tool that lies at exactly the moment it is needed.
  def self.render_signature(signature : Signature) : String
    String.build do |io|
      io << "abstract " if signature.required
      io << "def "
      io << signature.receiver << '.' unless signature.receiver.empty?
      io << signature.name

      parameters = signature.parameters
      block_parameter = signature.block_parameter
      unless parameters.empty? && block_parameter.empty?
        io << '('
        parameters.join(io, ", ")
        io << ", " unless parameters.empty? || block_parameter.empty?
        io << block_parameter
        io << ')'
      end

      io << " : " << signature.return_type unless signature.return_type.empty?

      free_variables = signature.free_variables
      unless free_variables.empty?
        io << " forall "
        free_variables.join(io, ", ")
      end
    end
  end

  private def self.encode_header(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_string io, artifact.module_name
    write_string io, artifact.source_path
    write_string io, artifact.compiler_version
    write_string io, artifact.target_triple
    io.write_bytes artifact.flags.size.to_u32, FORMAT
    artifact.flags.each { |flag| write_string io, flag }
    io.to_slice
  end

  private def self.decode_header(payload : Bytes)
    io = IO::Memory.new(payload)
    module_name = read_string(io)
    source_path = read_string(io)
    compiler_version = read_string(io)
    target_triple = read_string(io)
    flags = Array(String).new(io.read_bytes(UInt32, FORMAT)) { read_string(io) }
    {module_name: module_name, source_path: source_path,
     compiler_version: compiler_version, target_triple: target_triple, flags: flags}
  end

  private def self.encode_imports(artifact : Artifact) : Bytes
    io = IO::Memory.new
    io.write_bytes artifact.imports.size.to_u32, FORMAT
    artifact.imports.each { |name| write_string io, name }
    io.to_slice
  end

  private def self.decode_imports(payload : Bytes) : Array(String)
    io = IO::Memory.new(payload)
    Array(String).new(io.read_bytes(UInt32, FORMAT)) { read_string(io) }
  end

  private def self.encode_exports(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_signatures io, artifact.exports.functions

    types = artifact.exports.types
    io.write_bytes types.size.to_u32, FORMAT
    types.each do |declaration|
      write_string io, declaration.name
      write_string io, declaration.kind
      write_strings io, declaration.type_parameters
      write_strings io, declaration.assoc_types
      write_strings io, declaration.supertraits
      write_signatures io, declaration.methods
    end

    impls = artifact.exports.impls
    io.write_bytes impls.size.to_u32, FORMAT
    impls.each do |record|
      write_string io, record.trait_name
      write_string io, record.type_name
      write_strings io, record.trait_arguments
      write_strings io, record.free_variables
      write_pairs io, record.free_variable_bounds
      write_pairs io, record.assoc_types
    end

    io.to_slice
  end

  private def self.write_signatures(io : IO, signatures : Array(Signature)) : Nil
    io.write_bytes signatures.size.to_u32, FORMAT
    signatures.each do |signature|
      write_string io, signature.name
      write_string io, signature.receiver
      write_strings io, signature.parameters
      write_string io, signature.block_parameter
      write_string io, signature.return_type
      write_strings io, signature.free_variables
      io.write_byte(signature.required ? 1_u8 : 0_u8)
    end
  end

  private def self.read_signatures(io : IO) : Array(Signature)
    Array(Signature).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      receiver = read_string(io)
      parameters = read_strings(io)
      block_parameter = read_string(io)
      return_type = read_string(io)
      free_variables = read_strings(io)
      required = io.read_byte == 1_u8
      Signature.new(name, receiver, parameters, block_parameter, return_type,
        free_variables, required)
    end
  end

  private def self.decode_exports(payload : Bytes) : Exports
    io = IO::Memory.new(payload)
    functions = read_signatures(io)

    types = Array(TypeDecl).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      kind = read_string(io)
      parameters = read_strings(io)
      assoc_types = read_strings(io)
      supertraits = read_strings(io)
      TypeDecl.new(name, kind, parameters, assoc_types, supertraits, read_signatures(io))
    end

    impls = Array(ImplRecord).new(io.read_bytes(UInt32, FORMAT)) do
      trait_name = read_string(io)
      type_name = read_string(io)
      trait_arguments = read_strings(io)
      free_variables = read_strings(io)
      free_variable_bounds = read_pairs(io)
      ImplRecord.new(trait_name, type_name, trait_arguments, free_variables,
        free_variable_bounds, read_pairs(io))
    end

    Exports.new(functions, types, impls)
  end

  private def self.write_strings(io : IO, values : Array(String)) : Nil
    io.write_bytes values.size.to_u32, FORMAT
    values.each { |value| write_string io, value }
  end

  private def self.read_strings(io : IO) : Array(String)
    Array(String).new(io.read_bytes(UInt32, FORMAT)) { read_string(io) }
  end

  private def self.write_pairs(io : IO, values : Array({String, String})) : Nil
    io.write_bytes values.size.to_u32, FORMAT
    values.each do |(first, second)|
      write_string io, first
      write_string io, second
    end
  end

  private def self.read_pairs(io : IO) : Array({String, String})
    Array({String, String}).new(io.read_bytes(UInt32, FORMAT)) do
      {read_string(io), read_string(io)}
    end
  end

  private def self.write_string(io : IO, value : String) : Nil
    io.write_bytes value.bytesize.to_u32, FORMAT
    io.write value.to_slice
  end

  private def self.read_string(io : IO) : String
    size = io.read_bytes(UInt32, FORMAT)
    bytes = Bytes.new(size)
    io.read_fully(bytes)
    String.new(bytes)
  end
end
