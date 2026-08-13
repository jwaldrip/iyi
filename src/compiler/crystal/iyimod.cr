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
# `Hashes`, `Exports`, `MacroBodies`, `MonoBodies` and `ObjectCode` are named in
# `Section` and not written. The kinds are declared now so that a file written
# today is readable by the compiler that adds them: an unknown section is
# skipped, a known one that is absent is simply absent.
module Crystal::IyiMod
  MAGIC = "IYIMOD\0\0".to_slice

  # Bumped when the layout of any section changes incompatibly. IV.5: a
  # `.iyimod` from another version is rejected and rebuilt, never migrated.
  FORMAT_VERSION = 2_u32

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
  record Signature,
    name : String,
    parameters : Array({String, String}),
    return_type : String

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
  # Type declarations, layout templates, type descriptors, trait declarations,
  # impl records and constants. IV.2 names them all; this carries the first of
  # the list, module-level `pub def` signatures. Methods of exported types are
  # not here either, since the types themselves are not.
  record Exports,
    functions : Array(Signature)

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
                   @flags, @imports, @exports = Exports.new([] of Signature))
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
      exports = Exports.new([] of Signature)

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

    functions = artifact.exports.functions
    if functions.empty?
      io.puts "exports       (none)"
    else
      io.puts "exports"
      functions.each do |signature|
        parameters = signature.parameters.map { |(name, type)| "#{name} : #{type}" }
        arguments = parameters.empty? ? "" : "(#{parameters.join(", ")})"
        io.puts "  def #{signature.name}#{arguments} : #{signature.return_type}"
      end
    end

    # Said out loud on every dump, because an exported trait or type currently
    # leaves no trace in the file at all: without this line a reader would take
    # the list above for the module's whole surface, which is precisely the
    # mistake `.iyimod` cannot afford anyone making.
    io.puts
    io.puts "note          format v#{FORMAT_VERSION} carries module-level `pub def`"
    io.puts "              signatures only. Exported types, traits, impls and"
    io.puts "              constants are not in this file yet (SPEC.md IV.2)."
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
    functions = artifact.exports.functions
    io.write_bytes functions.size.to_u32, FORMAT
    functions.each do |signature|
      write_string io, signature.name
      io.write_bytes signature.parameters.size.to_u32, FORMAT
      signature.parameters.each do |(name, type)|
        write_string io, name
        write_string io, type
      end
      write_string io, signature.return_type
    end
    io.to_slice
  end

  private def self.decode_exports(payload : Bytes) : Exports
    io = IO::Memory.new(payload)
    functions = Array(Signature).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      parameters = Array({String, String}).new(io.read_bytes(UInt32, FORMAT)) do
        {read_string(io), read_string(io)}
      end
      Signature.new(name, parameters, read_string(io))
    end
    Exports.new(functions)
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
