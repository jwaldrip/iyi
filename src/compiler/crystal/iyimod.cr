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
# `Hashes` and `MacroBodies` are named in `Section` and not written. The kinds
# are declared now so that a file written today is readable by the compiler
# that adds them: an unknown section is skipped, a known one that is absent is
# simply absent.
module Crystal::IyiMod
  MAGIC = "IYIMOD\0\0".to_slice

  # Bumped when the layout of any section changes incompatibly. IV.5: a
  # `.iyimod` from another version is rejected and rebuilt, never migrated.
  FORMAT_VERSION = 11_u32

  FORMAT = IO::ByteFormat::LittleEndian

  enum Section : UInt16
    Header      = 1
    Hashes      = 2
    Imports     = 3
    Exports     = 4
    MacroBodies = 5
    MonoBodies  = 6
    ObjectCode  = 7

    # iyi: the module's own top-level code, as source text. Not in IV.1's
    # table, which had no place for the one part of a module that is neither a
    # declaration nor a body of one — see IV.1g.
    Initialiser = 8
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
  #
  # *fields* is the type's own instance variables, `{"@items", "Array(T)"}`.
  #
  # An implementation detail that has to travel anyway, which IV.2 admits in as
  # much: a consumer allocates the type, and allocating needs its size. Left
  # out, a consumer read `pub struct List(T)` as a struct with no fields and
  # generated a `List(Int32)::new` that allocated nothing while the module's
  # own code wrote to `@items`. That is not a missing feature, it is memory
  # corruption waiting for the rest of `ObjectCode` to stop failing at link.
  #
  # Inherited fields are not here. They belong to the supertype's declaration,
  # and a consumer that has this type has that one too.
  record TypeDecl,
    name : String,
    kind : String,
    type_parameters : Array(String),
    assoc_types : Array(String),
    supertraits : Array(String),
    fields : Array({String, String}),
    methods : Array(Signature)

  # How a body is found again on the far side.
  #
  # A container plus the whole of what distinguishes one overload from another,
  # which is the parameter list and the block. Text rather than an index,
  # because an index is a promise that two builds walked the same declarations
  # in the same order, and nothing in the format makes that true.
  def self.mono_body_key(container : String, signature : Signature) : String
    String.build do |io|
      io << container << '#' << signature.name
      io << '(' << signature.parameters.join(", ") << ')'
      io << signature.block_parameter
    end
  end

  # The container half of the key, for an impl.
  def self.mono_body_container(trait_name : String, type_name : String) : String
    "#{trait_name} for #{type_name}"
  end

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
  #
  # *methods* is what the impl defines. They are the impl's rather than the
  # target's: `impl Cmp for Int32` puts `cmp` on a prelude type, which is a
  # type this module does not export and cannot describe. Recording them
  # against the target would lose them entirely for every impl written in the
  # trait's module, which R-3 allows and `std/traits` is made of.
  record ImplRecord,
    trait_name : String,
    type_name : String,
    trait_arguments : Array(String),
    free_variables : Array(String),
    free_variable_bounds : Array({String, String}),
    assoc_types : Array({String, String}),
    methods : Array(Signature)

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
  # Layout templates, type descriptors and constants. Field lists are here, and
  # were the exception that proves the rule: a consumer can typecheck a call
  # against a signature without knowing how the receiver is laid out, and it
  # cannot *allocate* one.
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

  # One object file: the machine code for the definitions on one type.
  #
  # The unit is a whole object file rather than a filtered part of one because
  # codegen already splits that way — every method is emitted into the LLVM
  # module of the type that owns it, one object file per type. Measured on the
  # Kemal port: 23 units, and **no symbol is defined by two of them**. So "this
  # module's own definitions" is expressible as a set of whole units, which is
  # what makes carrying them a matter of copying bytes rather than of teaching
  # codegen a second way to lay out a program.
  #
  # *name* is the type whose unit this is, as codegen named it —
  # `Kemal::Router::Router`, or `Std::List::List(Int32)` for an instantiation.
  # Kept as the type name and not as the mangled filename because the filename
  # is a function of the name plus this compiler's own escaping rules, and the
  # name is the thing that means something on the far side.
  record ObjectUnit,
    name : String,
    code : Bytes

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

    # Whether the module has top-level code that has to run (III.5).
    #
    # In the artifact because it is what a consumer cannot find out any other
    # way: the initialiser is not a declaration, so it is not in this file and
    # a module read from here contributes none. Without the flag a build links
    # a program whose module never set itself up — correct-looking, and wrong.
    # With it, the build is refused and says so.
    getter has_initialiser : Bool

    # The `using` directives the module writes, as written (II.3).
    #
    # Not part of the module's surface — nothing here is reachable through it —
    # but part of what its surface *means*. A signature is stored as the
    # annotation the author wrote, and `pub def handle(ctx : Context)` resolves
    # `Context` through a `using` further up the file. The annotation travels;
    # so must what resolves it.
    getter usings : Array(String)

    # What another module may reach. See `Exports`.
    getter exports : Exports

    # The machine code for this module's own definitions. See `ObjectUnit`.
    #
    # Empty when the build that wrote this generated no code — `--emit-iyimod`
    # is allowed on a `--no-codegen` build, and an artifact from one carries
    # declarations and nothing to link. That is a build that produced no object
    # code rather than a module that has none, and the two are told apart by
    # the flag the build was given rather than by anything in the file.
    #
    # Settable, and the only field that is, because it is the only one that is
    # not known when the artifact is described. Everything else comes out of
    # semantic analysis; this comes out of codegen, which runs after — and the
    # rest has to be built before it, so that a rule broken in a signature is
    # reported without waiting for a link that was never going to happen.
    property object_code : Array(ObjectUnit)

    # The bodies a consumer has to compile itself, by `mono_body_key`.
    #
    # The two exceptions IV.2 already allows, arriving: a method of a generic
    # type and a trait's default method are both specialised by whoever uses
    # them, so no producer can emit their machine code and the body is the only
    # thing that can travel. Everything else keeps its body to itself.
    #
    # Carried as **source text**, like the declarations and for the same
    # reason: the parser that read the module is the one that should read it
    # back. IV.1's table says serialised typed IR, which is the faster answer
    # and the one with a second grammar to keep correct; it can replace this
    # without changing what travels.
    getter mono_bodies : Hash(String, String)

    # The module's own top-level code, as source text. Empty when it has none.
    #
    # The one part of a module that is neither a declaration nor the body of
    # one, and the part III.5 is about: it has to *run*, in DAG order, before
    # anything that imports this module. It travels because nothing else can
    # produce it — a consumer that never opens the source cannot invent the
    # module's constants, its proc literals, or the statements between them.
    #
    # Rendered back into the module's own namespace by `declarations`, so it
    # arrives where it was written and takes its place in the import order like
    # any module read from source. `has_initialiser` stays for what this cannot
    # carry: code inside a *type* body, which belongs to the type.
    getter initialiser : String

    def initialize(@module_name, @source_path, @compiler_version, @target_triple,
                   @flags, @imports, @usings = [] of String, @exports = Exports.empty,
                   @object_code = [] of ObjectUnit, @has_initialiser = false,
                   @mono_bodies = {} of String => String, @initialiser = "")
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

    # Between the declarations and the machine code, which is where it belongs:
    # a front-end reader needs it and a linker does not.
    unless artifact.mono_bodies.empty?
      sections << {Section::MonoBodies, encode_mono_bodies(artifact)}
    end

    unless artifact.initialiser.empty?
      sections << {Section::Initialiser, encode_initialiser(artifact)}
    end

    # Last, and omitted when there is nothing in it. A consumer reading
    # `Exports` seeks past this section rather than through it, and the further
    # it sits from the header the less of the file a front-end-only build has
    # to touch — object code is by far the largest thing in here.
    unless artifact.object_code.empty?
      sections << {Section::ObjectCode, encode_object_code(artifact)}
    end

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
  #
  # *want_object_code* is false by default because the reader that matters most
  # is `import`, and it is a front-end reader: it needs the declarations and has
  # no use for the machine code. Reading it anyway would put the largest section
  # in the file on the path of the pass this artifact exists to make fast.
  def self.read(path : String, want_object_code : Bool = false) : Artifact
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
      imports = {imports: [] of String, usings: [] of String}
      exports = Exports.empty
      object_code = [] of ObjectUnit
      mono_bodies = {} of String => String
      initialiser = ""

      table.each do |(kind, length)|
        section = Section.from_value?(kind)

        # The table's whole purpose, taken literally: a front-end-only build
        # never wants the object code, and reading it would be the largest read
        # in the file. Seek past it rather than allocate it.
        if section == Section::ObjectCode && !want_object_code
          file.skip length
          next
        end

        payload = Bytes.new(length)
        file.read_fully?(payload) || raise Error.new("#{path} ends inside a section")
        case section
        when Section::Header     then header = decode_header(payload)
        when Section::Imports    then imports = decode_imports(payload)
        when Section::Exports    then exports = decode_exports(payload)
        when Section::ObjectCode then object_code = decode_object_code(payload)
        when Section::MonoBodies  then mono_bodies = decode_mono_bodies(payload)
        when Section::Initialiser then initialiser = String.new(payload)
        else
          # Written by a later compiler, or a section this one does not need.
          # Skipping is the point of the table.
        end
      end

      unless header
        raise Error.new("#{path} has no header section")
      end

      Artifact.new(header[:module_name], header[:source_path], header[:compiler_version],
        header[:target_triple], header[:flags], imports[:imports], imports[:usings], exports,
        object_code, header[:has_initialiser], mono_bodies, initialiser)
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
    if artifact.has_initialiser
      io.puts "initialiser   has code this file cannot carry — cannot be linked against"
    elsif artifact.initialiser.empty?
      io.puts "initialiser   none"
    else
      io.puts "initialiser   #{artifact.initialiser.lines.size} line(s)"
    end
    if artifact.imports.empty?
      io.puts "imports       (none)"
    else
      io.puts "imports"
      artifact.imports.each { |name| io.puts "  #{name}" }
    end

    unless artifact.usings.empty?
      io.puts "usings"
      artifact.usings.each { |directive| io.puts "  #{directive}" }
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
        declaration.fields.each { |(name, type)| io.puts "    #{name} : #{type}" }
        declaration.methods.each { |signature| io.puts "    #{render_signature(signature)}" }
      end

      exports.impls.each do |record|
        io.puts "  #{render_impl_header(record)}"
        record.assoc_types.each { |(name, answer)| io.puts "    type #{name} = #{answer}" }
        record.methods.each { |signature| io.puts "    #{render_signature(signature)}" }
      end
    end

    bodies = artifact.mono_bodies
    if bodies.empty?
      io.puts "mono bodies   (none)"
    else
      io.puts "mono bodies"
      bodies.keys.sort!.each { |key| io.puts "  #{key}" }
    end

    object_code = artifact.object_code
    if object_code.empty?
      io.puts "object code   (none)"
    else
      io.puts "object code"
      object_code.each { |unit| io.puts "  #{unit.name} — #{unit.code.size} bytes" }
    end

    # Said out loud on every dump. What is missing is no longer whole
    # declarations but the parts of them codegen needs, and a reader has no way
    # to tell a field list that is absent from one that is empty.
    io.puts
    io.puts "note          format v#{FORMAT_VERSION} carries declarations,"
    io.puts "              signatures, field lists, and the object code of this"
    io.puts "              module's own non-generic types. Layout templates,"
    io.puts "              type descriptors and constants are not in this file"
    io.puts "              yet, and neither are the bodies a consumer has to"
    io.puts "              specialise (SPEC.md IV.2)."
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

    # The module's own imports, restated. A consumer needs them loaded before
    # these declarations mean anything — a signature here can name a type from
    # one of them — and writing them as `import` rather than resolving them
    # here means they are loaded by the same rule as any other import, artifact
    # or source, at most once, cycle-checked.
    unless artifact.imports.empty?
      io << '\n'
      artifact.imports.each { |name| io << "import " << name << '\n' }
    end

    # Inside the module, where the parser keeps a `using` — it resolves names
    # for this module's declarations and must not reach whoever reads them.
    unless artifact.usings.empty?
      io << '\n'
      artifact.usings.each { |directive| io << "using " << directive << '\n' }
    end

    exports = artifact.exports
    exports.functions.each do |signature|
      io << '\n'
      render_declaration io, signature, exported: true
    end

    bodies = artifact.mono_bodies

    exports.types.each do |declaration|
      io << "\npub " << render_type_header(declaration) << '\n'
      declaration.assoc_types.each { |name| io << "  type " << name << '\n' }
      # Before the methods, where they are written and where a reader looks for
      # them. They are also what a `def initialize` with no body leaves
      # unassigned, which is why they arrive declared rather than inferred.
      declaration.fields.each { |(name, type)| io << "  " << name << " : " << type << '\n' }
      declaration.methods.each do |signature|
        render_declaration io, signature, indent: "  ",
          body: bodies[mono_body_key(declaration.name, signature)]?
      end
      io << "end\n"
    end

    # After the types, because an impl needs its target declared and because
    # the requirement check reads the methods off the target rather than out of
    # the impl's body — which is what lets that body be empty here.
    exports.impls.each do |record|
      container = mono_body_container(record.trait_name, record.type_name)
      io << '\n' << render_impl_header(record) << '\n'
      record.assoc_types.each { |(name, answer)| io << "  type " << name << " = " << answer << '\n' }
      record.methods.each do |signature|
        render_declaration io, signature, indent: "  ",
          body: bodies[mono_body_key(container, signature)]?
      end
      io << "end\n"
    end

    # Last, so that everything it can name is already declared. Inside the
    # module, because the parser wrapped this whole text in one — which is what
    # puts the module's own code back in the namespace it was written in.
    unless artifact.initialiser.empty?
      io << '\n' << artifact.initialiser << '\n'
    end
  end

  # One `def`'s header, as the artifact carries it.
  #
  # A parameter travels whole, and everything that decorates the method travels
  # with it: the splat markers, the block parameter, `forall`, the receiver and
  # `abstract`. Each of those was left out once and each is needed by a
  # consumer that has only this file — a block cannot be typed without its
  # annotation, `Array(U)` does not resolve without the `forall` that
  # introduced `U`, and an `abstract def` a consumer took for a definition is a
  # requirement it would never be told it had missed.
  def self.signature(a_def : Def) : Signature
    check_block_annotated a_def

    parameters = a_def.args.map_with_index do |arg, index|
      a_def.splat_index == index ? "*#{arg}" : arg.to_s
    end
    if double_splat = a_def.double_splat
      parameters << "**#{double_splat}"
    end

    Signature.new(
      name: a_def.name,
      receiver: a_def.receiver.try(&.to_s) || "",
      parameters: parameters,
      block_parameter: a_def.block_arg.try { |arg| "&#{arg}" } || "",
      return_type: a_def.return_type.try(&.to_s) || "",
      free_variables: a_def.free_vars || [] of String,
      required: a_def.abstract?,
    )
  end

  # iyi: R-2 reaches the block parameter (SPEC.md IV.2).
  #
  # An exported `def` that takes a block has to say what the block is. R-2 asks
  # for full parameter and return types so that a consumer never infers
  # anything, and a block is the one parameter whose type used not to be
  # written down: `def namespace(path : String, &)` says a block arrives and
  # nothing about it. Inside the module that is enough, because `yield` is
  # right there. Through an artifact it is not — the body stays behind, and
  # what the block receives, returns, and is evaluated in are all in it.
  #
  # Refused where the module is compiled rather than where it is read, because
  # this is the author's to fix and the consumer would only be able to report
  # that somebody else's module cannot be read.
  #
  # Counted before it was ruled: one exported signature in the samples, Kemal's
  # `Router#namespace`, out of about eighty. That one uses `with sub_router
  # yield` — it changes what `self` means inside the block — which is the case
  # no annotation can express yet either. See SPEC.md IV.2.
  private def self.check_block_annotated(a_def : Def) : Nil
    return unless a_def.block_arity || a_def.block_arg
    return if a_def.block_arg.try(&.restriction)

    a_def.raise <<-MSG
      `#{a_def.name}` is exported and takes a block it does not describe

      R-2 asks an exported signature for full types so that a consumer infers \
      nothing, and a block parameter is a parameter. The body stays in this \
      module, so a module reading `#{a_def.name}` from its `.iyimod` has no \
      `yield` left to infer the block from.

      Annotate it — `& : Elem -> Nil` — or leave the def unexported.
      MSG
  end

  # Marks a parsed reconstruction as what it is.
  #
  # A `def` from an artifact is a header: a call to it is typed from its return
  # annotation instead of from the body that is not there. The block parameter
  # is marked used for the same reason — with no body there is no `yield` to
  # infer a block from, so the annotation is what types it, which is the path
  # a def taking `&block : A -> B` and calling it already takes.
  class DeclarationMarker < Visitor
    def visit(node : Def)
      # A def whose body travelled is not a header: the consumer compiles it
      # like any other, which is the whole point of `MonoBodies`. Marking it
      # would turn the body it was given back into an external declaration and
      # leave the symbol undefined again.
      return false unless node.body.is_a?(Nop)

      node.iyi_from_artifact = true
      node.uses_block_arg = true if node.block_arg.try(&.restriction)
      false
    end

    def visit(node : ASTNode)
      true
    end
  end

  private def self.render_declaration(io : IO, signature : Signature,
                                      exported = false, indent = "",
                                      body : String? = nil) : Nil
    io << indent
    io << "pub " if exported
    io << render_signature(signature) << '\n'
    # An `abstract def` ends at its signature. Anything else needs the `end`
    # its absent body would have carried.
    return if signature.required

    # A body only where one travelled (`MonoBodies`). Indented back under this
    # declaration, because what is stored is the body the author wrote and the
    # indentation it was written at is not a fact about it.
    body.try &.each_line do |line|
      io << indent << "  " << line << '\n'
    end

    io << indent << "end\n"
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
    io.write_byte(artifact.has_initialiser ? 1_u8 : 0_u8)
    io.to_slice
  end

  private def self.decode_header(payload : Bytes)
    io = IO::Memory.new(payload)
    module_name = read_string(io)
    source_path = read_string(io)
    compiler_version = read_string(io)
    target_triple = read_string(io)
    flags = Array(String).new(io.read_bytes(UInt32, FORMAT)) { read_string(io) }
    has_initialiser = io.read_byte == 1_u8
    {module_name: module_name, source_path: source_path,
     compiler_version: compiler_version, target_triple: target_triple, flags: flags,
     has_initialiser: has_initialiser}
  end

  private def self.encode_imports(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_strings io, artifact.imports
    write_strings io, artifact.usings
    io.to_slice
  end

  private def self.decode_imports(payload : Bytes)
    io = IO::Memory.new(payload)
    {imports: read_strings(io), usings: read_strings(io)}
  end

  private def self.encode_initialiser(artifact : Artifact) : Bytes
    artifact.initialiser.to_slice
  end

  private def self.encode_mono_bodies(artifact : Artifact) : Bytes
    io = IO::Memory.new
    bodies = artifact.mono_bodies
    io.write_bytes bodies.size.to_u32, FORMAT
    # Sorted, because a hash's order is not a fact about the module and an
    # artifact that changed between two identical builds would defeat IV.3.
    bodies.keys.sort!.each do |key|
      write_string io, key
      write_string io, bodies[key]
    end
    io.to_slice
  end

  private def self.decode_mono_bodies(payload : Bytes) : Hash(String, String)
    io = IO::Memory.new(payload)
    bodies = {} of String => String
    io.read_bytes(UInt32, FORMAT).times do
      key = read_string(io)
      bodies[key] = read_string(io)
    end
    bodies
  end

  private def self.encode_object_code(artifact : Artifact) : Bytes
    io = IO::Memory.new
    units = artifact.object_code
    io.write_bytes units.size.to_u32, FORMAT
    units.each do |unit|
      write_string io, unit.name
      io.write_bytes unit.code.size.to_u32, FORMAT
      io.write unit.code
    end
    io.to_slice
  end

  private def self.decode_object_code(payload : Bytes) : Array(ObjectUnit)
    io = IO::Memory.new(payload)
    Array(ObjectUnit).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      code = Bytes.new(io.read_bytes(UInt32, FORMAT))
      io.read_fully(code)
      ObjectUnit.new(name, code)
    end
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
      write_pairs io, declaration.fields
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
      write_signatures io, record.methods
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
      fields = read_pairs(io)
      TypeDecl.new(name, kind, parameters, assoc_types, supertraits, fields, read_signatures(io))
    end

    impls = Array(ImplRecord).new(io.read_bytes(UInt32, FORMAT)) do
      trait_name = read_string(io)
      type_name = read_string(io)
      trait_arguments = read_strings(io)
      free_variables = read_strings(io)
      free_variable_bounds = read_pairs(io)
      assoc_types = read_pairs(io)
      ImplRecord.new(trait_name, type_name, trait_arguments, free_variables,
        free_variable_bounds, assoc_types, read_signatures(io))
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
