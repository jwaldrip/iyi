require "option_parser"
require "file_utils"
require "colorize"
require "crystal/digest/md5"
{% if flag?(:msvc) %}
  require "./loader"
{% end %}
{% unless flag?(:without_mt) %}
  require "wait_group"
{% end %}

module Crystal
  # This exception describes an error in the compiler.
  # It usually leads to an unsuccessful process exit.
  class CompilerError < Exception
    getter status

    def self.new(message, exit : Command::Exit)
      new message, status: exit.to_i
    end

    def initialize(message, *, @status : Int32 = 1)
      super message
    end
  end

  @[Flags]
  enum Debug
    LineNumbers
    Variables
    Default     = LineNumbers
  end

  enum FramePointers
    Auto
    Always
    NonLeaf
  end

  # Main interface to the compiler.
  #
  # A Compiler parses source code, type checks it and
  # optionally generates an executable.
  class Compiler
    DEFAULT_LINKER = ENV["CC"]? || {{ env("CRYSTAL_CONFIG_CC") || "cc" }}
    MSVC_LINKER    = ENV["CC"]? || {{ env("CRYSTAL_CONFIG_CC") || "cl.exe" }}

    # A source to the compiler: its filename and source code.
    record Source,
      filename : String,
      code : String

    # The result of a compilation: the program containing all
    # the type and method definitions, and the parsed program
    # as an ASTNode.
    record Result,
      program : Program,
      node : ASTNode

    # If `true`, doesn't generate an executable but instead
    # creates a `.o` file and outputs a command line to link
    # it in the target machine.
    property? cross_compile = false

    # Compiler flags. These will be true when checked in macro
    # code by the `flag?(...)` macro method.
    property flags = [] of String

    # Controls generation of frame pointers.
    property frame_pointers = FramePointers::Auto

    # If `true`, the executable will be generated with debug code
    # that can be understood by `gdb` and `lldb`.
    property debug = Debug::Default

    # If `true`, `.ll` files will be generated in the default cache
    # directory for each generated LLVM module.
    property? dump_ll = false

    # Additional link flags to pass to the linker.
    property link_flags : String?

    # Sets the mcpu. Check LLVM docs to learn about this.
    property mcpu : String?

    # Sets the mattr (features). Check LLVM docs to learn about this.
    property mattr : String?

    # If `false`, color won't be used in output messages.
    property? color = true

    # If `true`, skip cleanup process on semantic analysis.
    property? no_cleanup = false

    # If `true`, no executable will be generated after compilation
    # (useful to type-check a program)
    property? no_codegen = false

    # Maximum number of LLVM modules that are compiled in parallel
    property n_threads : Int32 = {% if Fiber.has_constant?(:ExecutionContext) %}
      Fiber::ExecutionContext.default_workers_count
    {% elsif flag?(:win32) %}
      1
    {% else %}
      8
    {% end %}

    # Default prelude file to use. This ends up adding a
    # `require "prelude"` (or whatever name is set here) to
    # the source file to compile.
    property prelude = "prelude"

    # iyi: directory to write a `.iyimod` per imported module into, or nil
    # (SPEC.md IV.1). Set by `--emit-iyimod`.
    property emit_iyimod : String? = nil

    # iyi: directory to read a `.iyimod` per imported module from, or nil
    # (SPEC.md IV.1). Set by `--use-iyimod`. An import that finds one there is
    # compiled against it and never opens the module's source, which is R-1's
    # contract and the reason the file exists.
    property use_iyimod : String? = nil

    # Optimization mode
    enum OptimizationMode
      # [default] no optimization, fastest compilation, slowest runtime
      O0 = 0

      # low, compilation slower than O0, runtime faster than O0
      O1 = 1

      # middle, compilation slower than O1, runtime faster than O1
      O2 = 2

      # high, slowest compilation, fastest runtime
      # enables with --release flag
      O3 = 3

      # optimize for size, enables most O2 optimizations but aims for smaller
      # code size
      Os

      # optimize aggressively for size rather than speed
      Oz

      def suffix
        ".#{to_s.downcase}"
      end

      def self.from_level?(level : String) : self?
        case level
        when "0" then O0
        when "1" then O1
        when "2" then O2
        when "3" then O3
        when "s" then Os
        when "z" then Oz
        end
      end
    end

    # Sets the Optimization mode.
    property optimization_mode = OptimizationMode::O0

    # Sets the code model. Check LLVM docs to learn about this.
    property mcmodel = LLVM::CodeModel::Default

    # If `true`, generates a single LLVM module. By default
    # one LLVM module is created for each type in a program.
    # --release automatically enable this option
    property? single_module = false

    # A `ProgressTracker` object which tracks compilation progress.
    property progress_tracker = ProgressTracker.new

    # Codegen target to use in the compilation.
    # If not set, asks LLVM the default one for the current machine.
    property codegen_target = Config.host_target

    # If `true`, prints the link command line that is performed
    # to create the executable.
    property? verbose = false

    # If `true`, doc comments are attached to types and methods
    # and can later be used to generate API docs.
    property? wants_doc = false

    # Warning settings and all detected warnings.
    property warnings = WarningCollection.new

    @[Flags]
    enum EmitTarget
      ASM
      OBJ
      LLVM_BC
      LLVM_IR
    end

    # Can be set to a set of flags to emit other files other
    # than the executable file:
    # * asm: assembly files
    # * llvm-bc: LLVM bitcode
    # * llvm-ir: LLVM IR
    # * obj: object file
    property emit_targets : EmitTarget = EmitTarget::None

    # Base filename to use for `emit` output.
    property emit_base_filename : String?

    # By default the compiler cleans up the default cache directory
    # to keep the most recent 10 directories used. If this is set
    # to `false` that cleanup is not performed.
    property? cleanup = true

    # Default standard output to use in a compilation.
    property stdout : IO = STDOUT

    # Default standard error to use in a compilation.
    property stderr : IO = STDERR

    # Whether to show error trace
    property? show_error_trace = false

    # Whether to link statically
    property? static = false

    property dependency_printer : DependencyPrinter? = nil

    # Program that was created for the last compilation.
    property! program : Program

    # Compiles the given *source*, with *output_filename* as the name
    # of the generated executable.
    #
    # Raises `Crystal::CodeError` if there's an error in the
    # source code.
    #
    # Raises `InvalidByteSequenceError` if the source code is not
    # valid UTF-8.
    def compile(source : Source | Array(Source), output_filename : String) : Result
      compile_configure_program(source, output_filename) { }
    end

    # Compiles against an already-analysed prelude. This is the same split the
    # fork probe measures (SPEC.md IV.1a): the top-level pass runs over the user
    # file only, and every pass after it runs over both trees, because they walk
    # the prelude for reasons caching its analysis does not remove.
    private def compile_with_preanalysed_prelude(pre : Preanalysed, sources : Array(Source),
                                                 output_filename : String, & : Program -> Nil) : Result
      program = pre.program

      # The prelude was analysed against a placeholder filename. Adopt this
      # build's, so that anything derived from it — `__temp_` prefixes, error
      # locations — matches what a normal compile would produce.
      program.filename = sources.first.filename
      program.compiler = self
      program.progress_tracker = @progress_tracker
      yield program

      node = @progress_tracker.stage("Parse") do
        nodes = sources.map do |source|
          program.requires.add source.filename
          parse(program, source).as(ASTNode)
        end
        program.normalize(Expressions.from(nodes))
      end

      begin
        node, processor = program.top_level_semantic(node, processor: pre.processor)
        node = program.semantic_after_top_level(
          Expressions.from([pre.node, node] of ASTNode), processor,
          cleanup: !no_cleanup?)
      rescue ex : SkipMacroCodeCoverageException
        program.macro_expansion_error_hook.try &.call(ex.cause)
      end

      prepared = prepare_iyimods program

      units = codegen program, node, sources, output_filename unless @no_codegen

      write_iyimods program, prepared, units

      @progress_tracker.clear
      print_macro_run_stats(program)
      print_codegen_stats(units)

      Result.new program, node
    end

    # A prelude analysed ahead of a build, for a later compile to adopt instead
    # of analysing it again. The build daemon produces one before forking; the
    # child adopts it, which is where its speed comes from.
    class Preanalysed
      getter program : Program
      getter node : ASTNode
      getter processor : TypeDeclarationProcessor
      getter key : String

      # Every file the prelude pulled in, with the modification time it had when
      # it was read. A daemon outlives edits to its own sources, so serving a
      # build from an analysis of a since-edited prelude is the one way it can
      # be silently, confusingly wrong.
      getter fingerprint : Hash(String, Time)

      def initialize(@program, @node, @processor, @key)
        @fingerprint = {} of String => Time
        @program.requires.each do |filename|
          if info = File.info?(filename)
            @fingerprint[filename] = info.modification_time
          end
        end
      end

      # Whether the prelude on disk has moved out from under this analysis.
      # Files added since are not detectable from here — a new `require` in an
      # edited file shows up as that file's own mtime changing, which is what
      # actually triggers the reload.
      def stale? : Bool
        @fingerprint.any? do |filename, mtime|
          info = File.info?(filename)
          info.nil? || info.modification_time != mtime
        end
      end
    end

    # Set in the daemon before it forks, adopted by the child. Keyed by
    # `prelude_cache_key`, because a prelude analysed under one set of flags
    # cannot serve a build under another — macros branch on flags.
    class_property preanalysed = {} of String => Preanalysed

    # Everything that changes what the prelude analyses *to*. Macros branch on
    # flags, so a build whose key differs cannot adopt a prelude analysed under
    # another one and has to analyse its own.
    def prelude_cache_key : String
      String.build do |io|
        io << prelude << '|' << codegen_target << '|' << @optimization_mode << '|'
        io << debug << '|' << static? << '|' << wants_doc? << '|'
        io << @flags.sort.join(',')
      end
    end

    # Analyses the prelude on its own, so a later compile can start from it.
    # The filename is a placeholder: the build that adopts this has its own, and
    # sets it before compiling.
    def preanalyse_prelude : Preanalysed
      program = new_program([Source.new("", "")] of Source)
      location = Location.new(program.filename, 1, 1)
      node = program.normalize(Expressions.new([Require.new(prelude).at(location)] of ASTNode))
      node, processor = program.top_level_semantic(node)
      @progress_tracker.clear
      Preanalysed.new(program, node, processor, prelude_cache_key)
    end

    # :ditto:
    #
    # Yields a `Program` instance before compiling.
    def compile_configure_program(source : Source | Array(Source), output_filename : String, & : Program -> Nil) : Result
      source = [source] unless source.is_a?(Array)
      return prelude_fork_probe(source, output_filename) if ENV["IYI_FORK_PROBE"]?

      if pre = Compiler.preanalysed[prelude_cache_key]?
        return compile_with_preanalysed_prelude(pre, source, output_filename) { |program| yield program }
      end
      program = new_program(source)
      yield program
      node = parse program, source

      begin
        node = program.semantic node, cleanup: !no_cleanup?
      rescue ex : SkipMacroCodeCoverageException
        program.macro_expansion_error_hook.try &.call(ex.cause)
      end

      prepared = prepare_iyimods program

      units = codegen program, node, source, output_filename unless @no_codegen

      write_iyimods program, prepared, units

      @progress_tracker.clear
      print_macro_run_stats(program)
      print_codegen_stats(units)
      Prof.report

      Result.new program, node
    end

    # iyi: describes a `.iyimod` per imported module (SPEC.md IV.1), when
    # `--emit-iyimod` asked for it. Everything but the object code, which does
    # not exist yet — see `write_iyimods`.
    #
    # Only imported modules. The entry file is a program rather than a
    # dependency, and nothing can import it — III.5 rule 1 puts its initialiser
    # last for the same reason.
    #
    # The file is named after the module path with `/` kept, so `app/greeter`
    # lands at `DIR/app/greeter.iyimod` and the layout mirrors the source tree.
    # IV.6 #6's segment rule is what makes that safe: two module paths cannot
    # collide, so two modules cannot claim one artifact.
    #
    # Run before codegen, because collecting a module's surface is where R-2 is
    # enforced — an exported signature missing a block annotation is refused
    # here. Refusing it after a full codegen and link would make the compiler
    # spend the whole build on a program it had already decided not to write.
    private def prepare_iyimods(program : Program) : Array({String, IyiMod::Artifact})?
      return unless dir = emit_iyimod

      flags = program.flags.to_a.sort!

      # Before codegen, because that is what it is for: a method whose body is
      # a literal is inlined and emits no symbol, and this build is producing
      # code somebody else will call by name.
      program.iyi_module_paths.each_value do |module_name|
        if type = program.iyi_module_type(module_name)
          program.iyi_exported_owners << type
          collect_iyi_owners type, program.iyi_exported_owners
        end
      end

      program.iyi_module_paths.map do |filename, module_name|
        imports = program.iyi_module_imports[filename]?.try do |dependencies|
          dependencies.map { |dependency| program.iyi_module_paths[dependency]? || dependency }
        end

        artifact = IyiMod::Artifact.new(
          module_name: module_name,
          source_path: filename,
          # Not `Config.description`: that is the multi-line `--version` banner,
          # and this field is compared for equality (IV.5).
          compiler_version: IyiMod.compiler_version,
          target_triple: program.codegen_target.to_s,
          flags: flags,
          imports: imports || [] of String,
          usings: program.iyi_usings[filename]? || [] of String,
          exports: collect_iyi_exports(program, module_name, filename),
          has_initialiser: program.iyi_module_initialisers.includes?(filename),
        )

        {File.join(dir, "#{module_name}.iyimod"), artifact}
      end
    end

    # iyi: attaches each module's object code and writes the artifacts.
    #
    # After codegen, because that is when the object files exist. Writing here
    # also says something true: an artifact is written by a build that got all
    # the way through, so a build that failed in codegen leaves the previous
    # artifact in place rather than a newer one describing a program that does
    # not link.
    private def write_iyimods(program : Program, prepared : Array({String, IyiMod::Artifact})?,
                              units : Array(CompilationUnit)?) : Nil
      return unless prepared

      units_by_name = units.try &.to_h { |unit| {unit.original_name, unit} }

      prepared.each do |(path, artifact)|
        artifact.object_code = collect_iyi_object_code(program, artifact.module_name, units_by_name)
        IyiMod.write artifact, path
      end
    end

    # iyi: a module's public surface, for the artifact's `Exports` (IV.2).
    #
    # `pub` records a *name* on the module (R-2), so this walks those names and
    # takes the signature of each `def` they resolve to. A name can carry
    # several overloads and each is its own signature.
    #
    # Parameter and return types are the annotations as written. R-2 requires
    # them on anything exported, so an export missing one is not a signature to
    # infer but a rule that was broken somewhere else; it is recorded as `?`
    # rather than guessed at, which keeps that visible in `mod dump` instead of
    # inventing a type the author never wrote.
    private def collect_iyi_exports(program : Program, module_name : String,
                                    filename : String) : IyiMod::Exports
      functions = [] of IyiMod::Signature
      types = [] of IyiMod::TypeDecl

      if type = program.iyi_module_type(module_name)
        if exported = type.exported_names
          exported.to_a.sort!.each do |name|
            # A name is a function or a type, never both: they share one
            # namespace on the module, which is what makes `pub` a mark on a
            # name rather than on a kind of declaration.
            if signatures = type.defs.try &.[]?(name)
              signatures.each { |item| functions << IyiMod.signature(item.def) }
            elsif exported_type = type.types?.try &.[]?(name)
              types << iyi_type_declaration(name, exported_type)
            end
          end
        end
      end

      impls = program.iyi_impls[filename]? || [] of IyiMod::ImplRecord

      IyiMod::Exports.new(functions, types, impls)
    end

    # iyi: the machine code for a module's own definitions, for `ObjectCode`
    # (IV.1). Empty on a `--no-codegen` build, which generated none.
    #
    # Codegen already emits one LLVM module — and so one object file — per
    # owner type, and the split is a partition: measured on the Kemal port, no
    # symbol is defined by two of its 23 units. So a module's own code is a set
    # of whole object files, identified by naming the types the module declares
    # and taking the unit of each. A generic type contributes one unit per
    # instantiation, and a module's own `pub def`s are owned by the module type
    # itself, which is why that is in the set alongside the types under it.
    #
    # **Two gaps, both said out loud because neither is obvious from the file.**
    #
    # A module's bodies also instantiate *prelude* generics at its own types —
    # `Array(Kemal::Router::Router::RouteDefinition)` — and those units are
    # named after `Array`, not after anything this module declares. A consumer
    # compiling against the artifact never sees the body that needs them, so
    # nothing generates them and nothing else can: they are undefined at link.
    # Twelve of the router's 41 undefined symbols are of this kind. They belong
    # to this module by the same logic R-3 uses for impls, and attaching them
    # is the next step rather than an oversight.
    #
    # And what is here is what the *consuming build* reached, not the module's
    # whole surface. Codegen is demand-driven, so `app/greeter`'s artifact
    # carries `polite` and not `title`, because `modules.iyi` calls one and not
    # the other. That is `--emit-iyimod` living inside an ordinary build: a
    # module compiled on its own would instantiate every exported def at the
    # signature R-2 makes it write down, and it is exactly the command that
    # cannot precede the artifact it produces.
    private def collect_iyi_object_code(program : Program, module_name : String,
                                        units_by_name : Hash(String, CompilationUnit)?) : Array(IyiMod::ObjectUnit)
      code = [] of IyiMod::ObjectUnit
      return code unless units_by_name
      return code unless type = program.iyi_module_type(module_name)

      names = [] of String
      names << type.to_s
      collect_iyi_unit_names type, names
      names.sort!.uniq!

      names.each do |name|
        next unless unit = units_by_name[name]?
        path = unit.object_name
        next unless File.file?(path)
        code << IyiMod::ObjectUnit.new(name, File.open(path, "rb", &.getb_to_end))
      end
      code
    end

    # The unit names of every type declared under *type*, recursively.
    #
    # A unit is named after the type that owns the methods in it, and **a
    # generic type's instantiations are deliberately not here**. `List(T)` has
    # no machine code; only `List(Int32)` does, and which instantiations exist
    # is decided by whoever writes `List(Int32)` — under separate compilation
    # the consumer, not this module. Those are `MonoBodies`' business (IV.2).
    #
    # Carrying them was tried and is wrong, in a way worth recording because it
    # looks right. `--emit-iyimod` runs inside an ordinary build, so the
    # producer's instantiations *are* the consumer's — it appears to work. It
    # does not: `List(Int32)::new` is synthesized from `initialize` rather than
    # read from the artifact, so the consumer generates its own and the link
    # fails on a duplicate symbol. Carrying an instantiation would also be true
    # only while the two builds are the same build, which is the arrangement
    # this file exists to end.
    private def collect_iyi_unit_names(type : ModuleType, names : Array(String)) : Nil
      type.types?.try &.each_value do |declared|
        names << declared.to_s unless declared.is_a?(GenericType)
        collect_iyi_unit_names declared, names if declared.is_a?(ModuleType)
      end
    end

    # The same walk as `collect_iyi_unit_names`, keeping the types rather than
    # their names — `try_inline_call` is handed an owner, not a string.
    private def collect_iyi_owners(type : ModuleType, owners : Set(Type)) : Nil
      type.types?.try &.each_value do |declared|
        owners << declared unless declared.is_a?(GenericType)
        collect_iyi_owners declared, owners if declared.is_a?(ModuleType)
      end
    end

    # A trait's methods are its whole point in the artifact: II.6 makes an impl
    # checkable against the trait's requirements, and a consumer can only run
    # that check if the requirements travel. Its defaults travel as signatures
    # too — the body stays behind, since the consumer calls it rather than
    # reimplementing it.
    private def iyi_type_declaration(name : String, type : Type) : IyiMod::TypeDecl
      methods = [] of IyiMod::Signature
      type.as?(ModuleType).try &.defs.try &.each_value do |items|
        # A method an `impl` defined is the impl's, and travels in its record.
        # The distinction is invisible here — an impl works by defining methods
        # on the target — which is why it is marked where it is made.
        items.each { |item| methods << IyiMod.signature(item.def) unless item.def.iyi_from_impl? }
      end
      methods.sort_by! &.name

      # A generic trait's type variables are its parameters followed by its
      # associated types, which is how they are stored and not how they are
      # declared. They are split apart again here, because II.6 makes them
      # different things to a consumer: it supplies the first at the `impl`
      # line and answers the second in the body.
      if generic_trait = type.as?(GenericTraitType)
        type_parameters = generic_trait.trait_params
        assoc_types = generic_trait.assoc_types
      else
        type_parameters = type.as?(GenericType).try(&.type_vars) || [] of String
        assoc_types = [] of String
      end

      IyiMod::TypeDecl.new(
        name: name,
        kind: type.type_desc,
        type_parameters: type_parameters,
        assoc_types: assoc_types,
        supertraits: type.responds_to?(:supertraits) ? type.supertraits.map(&.to_s) : [] of String,
        fields: collect_iyi_fields(type),
        methods: methods,
      )
    end

    # iyi: a type's own instance variables, for `TypeDecl#fields` (IV.2).
    #
    # Rendered from the resolved type rather than kept as the annotation the
    # author wrote, which is a departure from how signatures travel and is
    # deliberate: a field is not part of the surface a consumer writes against,
    # it is what the consumer has to *allocate*, and the resolved type is the
    # thing that answers that. For a generic type the resolution is in terms of
    # its own parameters — `List(T)`'s `@items` is `Array(T)` — which is what
    # lets the declaration stencil at any instantiation.
    #
    # Sorted, because a hash's order is not a fact about the type and an
    # artifact that changed byte for byte between two identical builds would
    # defeat IV.3's whole purpose before it is written.
    private def collect_iyi_fields(type : Type) : Array({String, String})
      fields = [] of {String, String}
      return fields unless type.responds_to?(:instance_vars)

      type.instance_vars.each do |name, variable|
        # A variable whose type never resolved is a rule broken elsewhere, and
        # recorded as `?` rather than guessed at — the same convention an
        # unannotated signature takes, and equally visible in `mod dump`.
        fields << {name, variable.type?.try(&.to_s) || "?"}
      end
      fields.sort_by! { |(name, _)| name }
      fields
    end

    # Measures what a compile costs when the prelude has already been analysed,
    # gated behind IYI_FORK_PROBE=1. Temporary instrumentation, like `Prof`.
    #
    # The parent runs the top-level passes over the prelude alone and forks. The
    # child then compiles the user program against a `Program` that already has
    # the prelude in it, so restoring the prelude costs it a `fork` — around a
    # millisecond, a floor no serialised `.iyimod` can beat. The child's elapsed
    # time is therefore the ceiling of the whole `.iyimod` idea, obtainable
    # without designing the format.
    #
    # Front-end only: the child stops after semantic analysis. Codegen and
    # linking are LLVM's and the linker's problem, and `.iyimod`'s object-code
    # section addresses them separately.
    #
    # Known limit: compiling the compiler itself still fails under both models —
    # a `NilAssertionError` in `add_instance_var_initializer` under the artifact
    # model, and an error during the top-level pass under the full one. The
    # split runs `TypeDeclarationProcessor` twice, and part of its work is
    # global rather than per-tree, so the second run does not see everything the
    # first established. The nine smaller programs in the gate do not exercise
    # that. This is the next thing to fix before the probe becomes a build
    # daemon, and it is a real defect rather than a measurement caveat.
    #
    # Set IYI_FORK_TRACE=1 to see how far the child gets, and
    # IYI_FORK_SELFTEST=1 to check the runtime facilities a build needs (file
    # write, flock, subprocess) before it starts.
    #
    # Two models, because they answer different questions:
    #
    # * `IYI_FORK_PROBE=1` — the artifact exactly as Part IV describes it. The
    #   parent runs only the *top-level* passes over the prelude, so the child
    #   still walks the combined tree in every pass after that, and three passes
    #   still walk the whole type graph. That residual is the work a `.iyimod`
    #   would not remove on its own.
    #
    # * `IYI_FORK_PROBE=full` — the artifact *plus* prelude-aware passes. The
    #   parent analyses the prelude completely and the child touches only its
    #   own nodes. This prices IV.1a's third row: what the later passes would
    #   have to become for the front end to reach its floor.
    #
    #   It is 10× faster than the artifact model on the small programs in the
    #   gate, where it also reports what a normal compile reports and emits an
    #   object with an identical symbol table.
    #
    #   It does not work on real code, and the reason is structural rather than
    #   incidental: analysing the prelude *through `main`* and then declaring new
    #   types into it re-enters machinery that assumes declaration precedes
    #   typing. Subclassing a prelude type is enough to trip it — see SPEC.md
    #   IV.1e. Part IV's artifact carries types and signatures, not typed method
    #   bodies, so this model measures more than `.iyimod` restores. Treat its
    #   numbers as a ceiling on a configuration that does not work.
    #
    #   One trap, because it looks like a soundness failure and is not. Give
    #   codegen only the user tree and it dies with:
    #
    #     Missing __crystal_raise_overflow function
    #
    #   That is a `fun` in `src/raise.cr`, and codegen emits `fun`s and top-level
    #   code by walking the AST — so the prelude's tree has to reach codegen no
    #   matter what the front end did with it. That is the artifact's
    #   object-code section, not its analysis cache: the two need the prelude for
    #   different reasons.
    private def prelude_fork_probe(sources : Array(Source), output_filename : String) : NoReturn
      {% unless flag?(:without_mt) %}
        STDERR.puts "IYI_FORK_PROBE needs a single-threaded compiler: make crystal sequential_codegen=1"
        exit 1
      {% else %}
        program = new_program(sources)
        full = ENV["IYI_FORK_PROBE"]? == "full"

        prelude_elapsed = Time.instant
        location = Location.new(program.filename, 1, 1)
        prelude_node = program.normalize(Expressions.new([Require.new(prelude).at(location)] of ASTNode))
        prelude_node, prelude_processor = program.top_level_semantic(prelude_node)
        if full
          # Keep what it returns: the cleanup transformer rewrites the tree, and
          # codegen needs the rewritten one — the original still holds an
          # unexpanded `require`.
          prelude_node = program.semantic_after_top_level(prelude_node, prelude_processor, cleanup: !no_cleanup?)
        end
        prelude_taken = prelude_elapsed.elapsed
        @progress_tracker.clear

        probe_trace "[probe] parent: forking\n"
        pid = Crystal::System::Process.fork do
          probe_trace "[probe] child: alive\n"
          if ENV["IYI_FORK_SELFTEST"]?
            # Which runtime facility does a forked child actually lose? Each of
            # these is something a build needs, so whichever hangs is the one
            # standing between the probe and a real build daemon.
            probe_trace "[probe] selftest: file write\n"
            File.write("/tmp/iyi_probe_selftest", "x")
            probe_trace "[probe] selftest: flock\n"
            File.open("/tmp/iyi_probe_selftest", "w") { |f| f.flock_exclusive { } }
            probe_trace "[probe] selftest: subprocess\n"
            ::Process.run("true", shell: true)
            probe_trace "[probe] selftest: all passed\n"
          end
          child_elapsed = Time.instant
          begin
            nodes = sources.map do |source|
              program.requires.add source.filename
              parse(program, source).as(ASTNode)
            end
            probe_trace "[probe] child: parsed\n"
            user_node = program.normalize(Expressions.from(nodes))

            # Continue with the parent's processor: `Socket` is declared here but
            # includes `IO::Buffered`, which was declared there, and only a
            # shared processor gives the class the module's instance variables.
            user_node, processor = program.top_level_semantic(user_node, processor: prelude_processor)
            probe_trace "[probe] child: top level done\n"

            result = if full
              # Prelude fully analysed in the parent, including its class-var
              # check, so the child finishes over its own nodes alone.
              program.semantic_after_top_level(user_node, processor, cleanup: !no_cleanup?)
            else
              # The prelude was processed by the parent's own processor, so its
              # class-var check has to be threaded through as well, or the child
              # would skip a check a normal compile performs.
              combined = Expressions.from([prelude_node, user_node] of ASTNode)
              program.semantic_after_top_level(combined, processor,
                cleanup: !no_cleanup?, also_check: prelude_processor)
            end
            probe_trace "[probe] child: semantic done\n"

            # Proving the child's typed program is *codegen-able* is a stronger
            # claim than proving it reports the same diagnostics, so
            # IYI_FORK_CODEGEN=1 goes on to emit object code. Pair it with
            # `--cross-compile` and expect it to write the object and then hang:
            # everything after the emit spawns a subprocess, which is the one
            # thing the forked child cannot do. Kill it and compare the object.
            #
            # It is a verification tool, not a timing one — it never completes,
            # so it stays off by default and out of every measurement.
            if !@no_codegen && ENV["IYI_FORK_CODEGEN"]?
              # Codegen emits `fun` definitions and top-level code by walking the
              # AST, so it needs the prelude's tree even when the front end did
              # not. That is not a fudge: it is what Part IV's object-code
              # section means — the prelude's machine code comes from the
              # artifact rather than from re-analysing its source. Skipping the
              # prelude in the *front end* is the claim under test; skipping it
              # in codegen too would just be leaving the program half-emitted.
              to_emit = full ? Expressions.from([prelude_node, result] of ASTNode) : result
              codegen program, to_emit, sources, output_filename
              probe_trace "[probe] child: codegen done\n"
            end
          rescue ex : Crystal::CodeError
            # Same decision the driver makes in `Command#run`, so the child's
            # diagnostics are byte-identical to a normal compile's.
            ex.color = color? && Colorize.default_enabled?(STDOUT, STDERR)
            ex.error_trace = show_error_trace?
            STDERR.puts ex
            report_probe(prelude_taken, child_elapsed.elapsed)
            STDOUT.flush
            STDERR.flush
            LibC._exit 1
          end

          report_probe(prelude_taken, child_elapsed.elapsed)
          STDOUT.flush
          STDERR.flush
          LibC._exit 0
        end

        status = ::Process.new(Crystal::System::Process.new(pid.not_nil!)).wait
        exit status.exit_code
      {% end %}
    end

    # Unbuffered and allocation-free, so it still reports if the child is wedged
    # on the event loop or on the collector. Pass string literals only.
    # Resolved in the parent, before the fork, so the child never has to touch
    # ENV (which allocates) just to decide whether to trace.
    PROBE_TRACE = !ENV["IYI_FORK_TRACE"]?.nil?

    private def probe_trace(msg : String) : Nil
      return unless PROBE_TRACE
      LibC.write(2, msg.to_unsafe.as(Void*), LibC::SizeT.new(msg.bytesize))
    end

    private def report_probe(prelude_taken : Time::Span, child_taken : Time::Span) : Nil
      @progress_tracker.clear
      Prof.report
      STDERR.puts
      STDERR.puts "=== IYI_FORK_PROBE ==="
      STDERR.puts "prelude top level (parent, paid once) #{prelude_taken}"
      STDERR.puts "front end with prelude already analysed #{child_taken}"
    end

    # Runs the semantic pass on the given source, without generating an
    # executable nor analyzing methods. The returned `Program` in the result will
    # contain all types and methods. This can be useful to generate
    # API docs, analyze type relationships, etc.
    #
    # Raises `Crystal::CodeError` if there's an error in the
    # source code.
    #
    # Raises `InvalidByteSequenceError` if the source code is not
    # valid UTF-8.
    def top_level_semantic(source : Source | Array(Source)) : Result
      source = [source] unless source.is_a?(Array)
      program = new_program(source)
      node = parse program, source
      node, _ = program.top_level_semantic(node)

      @progress_tracker.clear
      print_macro_run_stats(program)

      Result.new program, node
    end

    # Set maximum level of optimization.
    def release!
      @optimization_mode = OptimizationMode::O3
      @single_module = true
    end

    def release?
      @optimization_mode.o3? && @single_module
    end

    private def new_program(sources)
      @program = program = Program.new
      program.compiler = self
      program.filename = sources.first.filename
      program.codegen_target = codegen_target
      program.target_machine = create_target_machine
      program.flags << "release" if release?
      program.flags << "debug" unless debug.none?
      program.flags << "static" if static?
      program.flags.concat @flags
      program.wants_doc = wants_doc?
      program.color = color?
      program.stdout = stdout
      program.show_error_trace = show_error_trace?
      program.progress_tracker = @progress_tracker
      program.warnings = @warnings
      program.optimization_mode = @optimization_mode
      program.iyi_module_dir = @use_iyimod
      program.iyi_wants_object_code = !@no_codegen
      program
    end

    private def parse(program, sources : Array)
      @progress_tracker.stage("Parse") do
        nodes = sources.map do |source|
          # We add the source to the list of required file,
          # so it can't be required again
          program.requires.add source.filename
          parse(program, source).as(ASTNode)
        end
        nodes = Expressions.from(nodes)

        # Prepend the prelude to the parsed program
        location = Location.new(program.filename, 1, 1)
        nodes = Expressions.new([Require.new(prelude).at(location), nodes] of ASTNode)

        # And normalize
        program.normalize(nodes)
      end
    end

    private def parse(program, source : Source)
      parser = program.new_parser(source.code)
      parser.filename = source.filename
      parser.wants_doc = wants_doc?
      parser.parse
    rescue ex : InvalidByteSequenceError
      stderr.print colorize("Error: ").red.bold
      stderr.print colorize("file '#{Crystal.relative_filename(source.filename)}' is not a valid Crystal source file: ").bold
      stderr.puts ex.message
      exit 1
    end

    private def bc_flags_changed?(output_dir)
      bc_flags_changed = true
      current_bc_flags = "#{@codegen_target}|#{@mcpu}|#{@mattr}|#{@link_flags}|#{@mcmodel}"
      bc_flags_filename = "#{output_dir}/bc_flags#{optimization_mode.suffix}"
      if File.file?(bc_flags_filename)
        previous_bc_flags = File.read(bc_flags_filename).strip
        bc_flags_changed = previous_bc_flags != current_bc_flags
      end
      File.write(bc_flags_filename, current_bc_flags)
      bc_flags_changed
    end

    private def codegen(program, node : ASTNode, sources, output_filename)
      {% if LibLLVM::IS_LT_130 %}
        if @codegen_target.architecture == "aarch64"
          stderr.puts "Error: Target #{@codegen_target} requires a Crystal compiler built with LLVM 13 or a later version."
          exit 1
        end
      {% end %}

      llvm_modules = @progress_tracker.stage("Codegen (crystal)") do
        program.codegen node, debug: debug, frame_pointers: frame_pointers,
          single_module: @single_module || @cross_compile || !@emit_targets.none?
      end

      output_dir = CacheDir.instance.directory_for(sources)

      bc_flags_changed = bc_flags_changed? output_dir
      target_triple = target_machine.triple

      units = llvm_modules.map do |type_name, info|
        llvm_mod = info.mod
        llvm_mod.target = target_triple
        CompilationUnit.new(self, program, type_name, llvm_mod, output_dir, bc_flags_changed)
      end

      {% if LibLLVM::IS_LT_170 %}
        # initialize the legacy pass manager once in the main thread/process
        # before we start codegen in threads (MT) or processes (fork)
        init_llvm_legacy_pass_manager unless optimization_mode.o0?
      {% end %}

      if @cross_compile
        cross_compile program, units, output_filename
      else
        units = with_file_lock(output_dir) do
          codegen program, units, output_filename, output_dir
        end

        {% if flag?(:darwin) %}
          run_dsymutil(output_filename) unless debug.none?
        {% end %}

        {% if flag?(:msvc) %}
          copy_dlls(program, output_filename) unless static?
        {% end %}
      end

      CacheDir.instance.cleanup if @cleanup

      units
    end

    private def with_file_lock(output_dir, &)
      File.open(File.join(output_dir, "compiler.lock"), "w") do |file|
        file.flock_exclusive do
          yield
        end
      end
    end

    private def run_dsymutil(filename)
      dsymutil = Process.find_executable("dsymutil")
      return unless dsymutil

      @progress_tracker.stage("dsymutil") do
        Process.run(dsymutil, ["--flat", filename])
      end
    end

    private def copy_dlls(program, output_filename)
      not_found = nil
      output_directory = File.dirname(output_filename)

      program.each_dll_path do |path, found|
        if found
          dest = File.join(output_directory, File.basename(path))
          File.copy(path, dest) unless File.exists?(dest)
        else
          not_found ||= [] of String
          not_found << path
        end
      end

      if not_found
        stderr << "Warning: The following DLLs are required at run time, but Crystal is unable to locate them in CRYSTAL_LIBRARY_PATH, the compiler's directory, or PATH: "
        not_found.sort!.join(stderr, ", ")
      end
    end

    private def cross_compile(program, units, output_filename)
      unit = units.first
      llvm_mod = unit.llvm_mod

      @progress_tracker.stage("Codegen (bc+obj)") do
        optimize llvm_mod, target_machine unless @optimization_mode.o0?

        unit.emit(@emit_targets, emit_base_filename || output_filename)

        target_machine.emit_obj_to_file llvm_mod, output_filename
      end
      object_names = [output_filename]
      output_filename = output_filename.rchop(unit.object_extension)
      _, command, args = linker_command(program, object_names, output_filename, nil)
      print_command(command, args)
    end

    private def print_command(command, args)
      stdout.puts command.sub(%("${@}"), args && Process.quote(args))
    end

    private def linker_command(program : Program, object_names, output_filename, output_dir, expand = false)
      if program.has_flag? "msvc"
        lib_flags = program.lib_flags(@cross_compile)
        lib_flags = expand_lib_flags(lib_flags) if expand

        object_arg = Process.quote_windows(object_names)
        output_arg = Process.quote_windows("/Fe#{output_filename}")

        linker, link_args = program.msvc_compiler_and_flags
        linker = Process.quote_windows(linker)
        link_args.map! { |arg| Process.quote_windows(arg) }

        link_args << "/DEBUG:FULL /PDBALTPATH:%_PDB%" unless debug.none?
        link_args << "/INCREMENTAL:NO /STACK:0x800000"
        link_args << lib_flags
        @link_flags.try { |flags| link_args << flags }

        {% if flag?(:msvc) %}
          unless @cross_compile
            extra_suffix = static? ? "-static" : "-dynamic"
            search_result = Loader.search_libraries(Process.parse_arguments_windows(link_args.join(' ').gsub('\n', ' ')), extra_suffix: extra_suffix)
            if not_found = search_result.not_found?
              raise CompilerError.new("Cannot locate the .lib files for the following libraries: #{not_found.join(", ")}", :FAILURE)
            end

            link_args = search_result.remaining_args.concat(search_result.library_paths).map { |arg| Process.quote_windows(arg) }
          end
        {% end %}

        args = %(/nologo #{object_arg} #{output_arg} /link #{link_args.join(' ')}).gsub("\n", " ")
        cmd = "#{linker} #{args}"

        if cmd.to_utf16.size > 32000
          # The command line would be too big, pass the args through a UTF-16-encoded file instead.
          # TODO: Use a proper way to write encoded text to a file when that's supported.
          # The first character is the BOM; it will be converted in the same endianness as the rest.
          args_16 = "\ufeff#{args}".to_utf16
          args_bytes = args_16.to_unsafe_bytes

          args_filename = "#{output_dir}/linker_args.txt"
          File.write(args_filename, args_bytes)
          cmd = "#{linker} #{Process.quote_windows("@" + args_filename)}"
        end

        {linker, cmd, nil}
      elsif program.has_flag? "wasm32"
        link_flags = @link_flags || ""
        {"wasm-ld", %(wasm-ld "${@}" -o #{Process.quote_posix(output_filename)} #{link_flags} -lc #{program.lib_flags(@cross_compile)}), object_names}
      elsif program.has_flag? "avr"
        link_flags = @link_flags || ""
        link_flags += " --target=avr-unknown-unknown -mmcu=#{@mcpu} -Wl,--gc-sections"
        {DEFAULT_LINKER, %(#{DEFAULT_LINKER} "${@}" -o #{Process.quote_posix(output_filename)} #{link_flags} #{program.lib_flags(@cross_compile)}), object_names}
      elsif program.has_flag?("win32") && program.has_flag?("gnu")
        link_flags = @link_flags || ""
        link_flags += " -Wl,--stack,0x800000"
        link_flags = use_modern_linker(link_flags)
        lib_flags = program.lib_flags(@cross_compile)
        lib_flags = expand_lib_flags(lib_flags) if expand
        cmd = %(#{DEFAULT_LINKER} #{Process.quote_windows(object_names)} -o #{Process.quote_windows(output_filename)} #{link_flags} #{lib_flags}).gsub('\n', ' ')

        if cmd.size > 32000
          # The command line would be too big, pass the args through a file instead.
          # GCC response file does not interpret those args as shell-escaped
          # arguments, we must rebuild the whole command line
          args_filename = "#{output_dir}/linker_args.txt"
          File.open(args_filename, "w") do |f|
            object_names.each do |object_name|
              f << object_name.gsub(GCC_RESPONSE_FILE_TR) << ' '
            end
            f << "-o " << output_filename.gsub(GCC_RESPONSE_FILE_TR) << ' '
            f << link_flags << ' ' << lib_flags
          end
          cmd = "#{DEFAULT_LINKER} #{Process.quote_windows("@" + args_filename)}"
        end

        {DEFAULT_LINKER, cmd, nil}
      else
        link_flags = @link_flags || ""
        link_flags += " -rdynamic"

        if program.has_flag?("freebsd") || program.has_flag?("openbsd")
          # pkgs are installed to usr/local/lib but it's not in LIBRARY_PATH by
          # default; we declare it to ease linking on these platforms:
          link_flags += " -L/usr/local/lib"
        end

        link_flags = use_modern_linker(link_flags)

        {DEFAULT_LINKER, %(#{DEFAULT_LINKER} "${@}" -o #{Process.quote_posix(output_filename)} #{link_flags} #{program.lib_flags(@cross_compile)}), object_names}
      end
    end

    # Tests if `mold` or `lld` are available and prefers them as linkers over
    # the default `ld`. Only works when `cc` is the linker driver and can be
    # disabled with `--link-flags=-fuse-ld=bfd`.
    private def use_modern_linker(link_flags)
      return link_flags unless DEFAULT_LINKER == "cc"
      return link_flags if link_flags.includes?("-fuse-ld=")

      if Process.find_executable("mold")
        link_flags + " -fuse-ld=mold"
      elsif Process.find_executable("ld.lld")
        link_flags + " -fuse-ld=lld"
      else
        link_flags
      end
    end

    private GCC_RESPONSE_FILE_TR = {
      " ":  %q(\ ),
      "'":  %q(\'),
      "\"": %q(\"),
      "\\": "\\\\",
    }

    private def expand_lib_flags(lib_flags)
      lib_flags.gsub(/`(.*?)`/) do
        command = $1
        begin
          error_io = IO::Memory.new
          output = Process.run(command, shell: true, output: :pipe, error: error_io) do |process|
            process.output.gets_to_end
          end
          unless $?.success?
            error_io.rewind
            raise CompilerError.new("Error executing subcommand for linker flags: #{command.inspect}: #{error_io}", :FAILURE)
          end
          output.chomp
        rescue exc
          raise CompilerError.new("Error executing subcommand for linker flags: #{command.inspect}: #{exc}", :FAILURE)
        end
      end
    end

    private def codegen(program, units : Array(CompilationUnit), output_filename, output_dir)
      object_names = units.map &.object_filename
      object_names.concat write_iyi_artifact_objects(program, output_dir)

      @progress_tracker.stage("Codegen (bc+obj)") do
        @progress_tracker.stage_progress_total = units.size

        n_threads = @n_threads.clamp(1..units.size)

        if n_threads == 1
          sequential_codegen(units)
        else
          parallel_codegen(units, n_threads)
        end

        if units.size == 1
          units.first.emit(@emit_targets, emit_base_filename || output_filename)
        end
      end

      # We check again because maybe this directory was created in between (maybe with a macro run)
      if Dir.exists?(output_filename)
        raise CompilerError.new("can't use `#{output_filename}` as output filename because it's a directory", :USAGE_ERROR)
      end

      output_filename = File.expand_path(output_filename)

      @progress_tracker.stage("Codegen (linking)") do
        Dir.cd(output_dir) do
          run_linker *linker_command(program, object_names, output_filename, output_dir, expand: true)
        end
      end

      units
    end

    # iyi: unpacks the object files imported artifacts carried, into the same
    # directory the build's own units go to, and returns their names for the
    # link (SPEC.md IV.1g).
    #
    # Written out rather than handed to the linker from memory because a linker
    # takes paths. They are named after the module and the unit so that two
    # modules carrying a unit for the same type — which cannot happen under
    # R-3, and which a corrupt or hand-made artifact could still ask for —
    # collide as two files rather than as one silently overwritten.
    private def write_iyi_artifact_objects(program, output_dir) : Array(String)
      names = [] of String
      extension = codegen_target.object_extension

      program.iyi_artifact_objects.each do |module_name, units|
        units.each do |unit|
          name = "iyimod-#{safe_object_name(module_name)}-#{safe_object_name(unit.name)}#{extension}"
          File.write File.join(output_dir, name), unit.code
          names << name
        end
      end

      names
    end

    # A module path or a type name as a filename. Neither is one — `app/greeter`
    # has a separator in it and `List(Int32)` has parentheses — and the point is
    # only that two different names cannot produce one file.
    private def safe_object_name(name : String) : String
      name.gsub(/[^A-Za-z0-9_]/) { |match| "-#{match[0].ord}" }
    end

    private def sequential_codegen(units)
      units.each do |unit|
        unit.compile
        @progress_tracker.stage_progress += 1
      end
    end

    private def parallel_codegen(units, n_threads)
      {% if !flag?(:without_mt) %}
        raise "LLVM isn't multithreaded and cannot fork compiler in multithread mode." unless LLVM.multithreaded?
        mt_codegen(units, n_threads)
      {% elsif LibC.has_method?("fork") %}
        fork_codegen(units, n_threads)
      {% else %}
        raise "Cannot fork compiler. `Crystal::System::Process.fork` is not implemented on this system."
      {% end %}
    end

    private def mt_codegen(units, n_threads)
      channel = Channel(CompilationUnit).new(n_threads * 2)
      wg = WaitGroup.new
      mutex = Sync::Mutex.new

      n_threads.times do
        wg.spawn do
          while unit = channel.receive?
            unit.compile(isolate_context: true)
            mutex.synchronize { @progress_tracker.stage_progress += 1 }
          end
        end
      end

      units.each do |unit|
        # We generate the bitcode in the main thread because LLVM contexts
        # must be unique per compilation unit, but we share different contexts
        # across many modules (or rely on the global context); trying to
        # codegen in parallel would segfault!
        #
        # Luckily generating the bitcode is quick and once the bitcode is
        # generated we don't need the global LLVM contexts anymore but can
        # parse the bitcode in an isolated context and we can parallelize the
        # slowest part: the optimization pass & compiling the object file.
        unit.generate_bitcode

        channel.send(unit)
      end
      channel.close

      wg.wait
    end

    private def fork_codegen(units, n_threads)
      workers = fork_workers(n_threads) do |input, output|
        while i = input.gets(chomp: true).presence
          unit = units[i.to_i]
          unit.compile
          result = {name: unit.name, reused: unit.reused_previous_compilation?}
          output.puts result.to_json
        end
      rescue ex
        result = {exception: {name: ex.class.name, message: ex.message, backtrace: ex.backtrace}}
        output.puts result.to_json
      end

      overqueue = 1
      indexes = Atomic(Int32).new(0)
      channel = Channel(String).new(n_threads)
      completed = Channel(Nil).new(n_threads)

      workers.each do |pid, input, output|
        spawn do
          overqueued = 0

          overqueue.times do
            if (index = indexes.add(1)) < units.size
              input.puts index
              overqueued += 1
            end
          end

          while (index = indexes.add(1)) < units.size
            input.puts index

            if response = output.gets(chomp: true)
              channel.send response
            else
              Crystal::System.print_error "\nBUG: a codegen process failed\n"
              exit 1
            end
          end

          overqueued.times do
            if response = output.gets(chomp: true)
              channel.send response
            else
              Crystal::System.print_error "\nBUG: a codegen process failed\n"
              exit 1
            end
          end

          input << '\n'
          input.close
          output.close

          Process.new(Crystal::System::Process.new(pid)).wait
          completed.send(nil)
        end
      end

      spawn do
        n_threads.times { completed.receive }
        channel.close
      end

      while response = channel.receive?
        result = JSON.parse(response)

        if ex = result["exception"]?
          Crystal::System.print_error "\nBUG: a codegen process failed: %s (%s)\n", ex["message"].as_s, ex["name"].as_s
          ex["backtrace"].as_a?.try(&.each { |frame| Crystal::System.print_error "  from %s\n", frame })
          exit 1
        end

        if @progress_tracker.stats?
          if result["reused"].as_bool
            name = result["name"].as_s
            unit = units.find! { |unit| unit.name == name }
            unit.reused_previous_compilation = true
          end
        end
        @progress_tracker.stage_progress += 1
      end
    end

    private def fork_workers(n_threads, &)
      workers = [] of {Int32, IO::FileDescriptor, IO::FileDescriptor}

      n_threads.times do
        iread, iwrite = IO.pipe
        oread, owrite = IO.pipe

        iwrite.flush_on_newline = true
        owrite.flush_on_newline = true

        pid = Crystal::System::Process.fork do
          iwrite.close
          oread.close

          yield iread, owrite

          iread.close
          owrite.close
          exit 0
        end

        iread.close
        owrite.close

        workers << {pid, iwrite, oread}
      end

      workers
    end

    private def print_macro_run_stats(program)
      return unless @progress_tracker.stats?
      return if program.compiled_macros_cache.empty?

      puts
      puts "Macro runs:"
      program.compiled_macros_cache.each do |filename, compiled_macro_run|
        print " - "
        print filename
        print ": "
        if compiled_macro_run.reused
          print "reused previous compilation (#{compiled_macro_run.elapsed})"
        else
          print compiled_macro_run.elapsed
        end
        puts
      end
    end

    private def print_codegen_stats(units)
      return unless @progress_tracker.stats?
      return unless units

      reused = units.count(&.reused_previous_compilation?)

      puts
      puts "Codegen (bc+obj):"
      case reused
      when units.size
        puts " - all previous .o files were reused"
      when .zero?
        puts " - no previous .o files were reused"
      else
        puts " - #{reused}/#{units.size} .o files were reused"
        puts
        puts "These modules were not reused:"
        units.each do |unit|
          next if unit.reused_previous_compilation?
          puts " - #{unit.original_name} (#{unit.name}.bc)"
        end
      end
    end

    getter(target_machine : LLVM::TargetMachine) do
      create_target_machine
    end

    def create_target_machine
      @codegen_target.to_target_machine(@mcpu || "", @mattr || "", @optimization_mode, @mcmodel)
    rescue ex : ArgumentError
      stderr.print colorize("Error: ").red.bold
      stderr.print "llc: "
      stderr.puts ex.message
      exit 1
    end

    {% if LibLLVM::IS_LT_170 %}
      property! pass_manager_builder : LLVM::PassManagerBuilder

      private def init_llvm_legacy_pass_manager
        registry = LLVM::PassRegistry.instance
        registry.initialize_all

        builder = LLVM::PassManagerBuilder.new
        builder.size_level = 0

        case optimization_mode
        in .o3?
          builder.opt_level = 3
          builder.use_inliner_with_threshold = 275
        in .o2?
          builder.opt_level = 2
          builder.use_inliner_with_threshold = 275
        in .o1?
          builder.opt_level = 1
          builder.use_inliner_with_threshold = 150
        in .o0?
          # default behaviour, no optimizations
        in .os?
          builder.opt_level = 2
          builder.size_level = 1
          builder.use_inliner_with_threshold = 50
        in .oz?
          builder.opt_level = 2
          builder.size_level = 2
          builder.use_inliner_with_threshold = 5
        end

        @pass_manager_builder = builder
      end

      private def optimize_with_pass_manager(llvm_mod)
        fun_pass_manager = llvm_mod.new_function_pass_manager
        pass_manager_builder.populate fun_pass_manager
        fun_pass_manager.run llvm_mod

        module_pass_manager = LLVM::ModulePassManager.new
        pass_manager_builder.populate module_pass_manager
        module_pass_manager.run llvm_mod
      end
    {% end %}

    protected def optimize(llvm_mod, target_machine)
      {% if LibLLVM::IS_LT_130 %}
        optimize_with_pass_manager(llvm_mod)
      {% else %}
        optimization_mode = @optimization_mode
        optimization_mode = OptimizationMode::O2 if optimization_mode.os? || optimization_mode.oz?

        LLVM::PassBuilderOptions.new do |options|
          LLVM.run_passes(llvm_mod, "default<#{optimization_mode}>", target_machine, options)
        end
      {% end %}
    end

    private def run_linker(linker_name, command, args)
      print_command(command, args) if verbose?

      begin
        Process.run(command, args, shell: true,
          input: Process::Redirect::Close, output: Process::Redirect::Inherit, error: Process::Redirect::Pipe) do |process|
          process.error.each_line(chomp: false) do |line|
            hint_string = colorize("(this usually means you need to install the development package for lib\\1)").yellow.bold
            line = line.gsub(/cannot find -l(\S+)\b/, "cannot find -l\\1 #{hint_string}")
            line = line.gsub(/unable to find library -l(\S+)\b/, "unable to find library -l\\1 #{hint_string}")
            line = line.gsub(/library not found for -l(\S+)\b/, "library not found for -l\\1 #{hint_string}")
            STDERR << line
          end
        end
      rescue exc : File::AccessDeniedError | File::NotFoundError
        linker_not_found exc.class, linker_name
      end

      status = $?
      unless status.success?
        exit_code = status.exit_code?
        case exit_code
        when 126
          linker_not_found File::AccessDeniedError, linker_name
        when 127
          linker_not_found File::NotFoundError, linker_name
        when nil
          # abnormal exit
          exit_code = 1
        end
        raise CompilerError.new("execution of command failed with exit status #{status}: #{command}", status: exit_code)
      end
    end

    private def linker_not_found(exc_class, linker_name)
      verbose_info = "\nRun with `--verbose` to print the full linker command." unless verbose?
      case exc_class
      when File::AccessDeniedError
        raise CompilerError.new("Could not execute linker: `#{linker_name}`: Permission denied#{verbose_info}", :FAILURE)
      else
        raise CompilerError.new("Could not execute linker: `#{linker_name}`: File not found#{verbose_info}", :FAILURE)
      end
    end

    private def colorize(obj)
      obj.colorize.toggle(@color)
    end

    # An LLVM::Module with information to compile it.
    class CompilationUnit
      getter compiler
      getter name
      getter original_name
      getter llvm_mod
      property? reused_previous_compilation = false
      getter object_extension : String
      @memory_buffer : LLVM::MemoryBuffer?
      @object_name : String?
      @bc_name : String?

      def initialize(@compiler : Compiler, program : Program, @name : String,
                     @llvm_mod : LLVM::Module, @output_dir : String, @bc_flags_changed : Bool)
        @name = "_main" if @name == ""
        @original_name = @name
        @name = String.build do |str|
          @name.each_char do |char|
            case char
            when 'a'..'z', '0'..'9', '_'
              str << char
            when 'A'..'Z'
              # Because OSX has case insensitive filenames, try to avoid
              # clash of 'a' and 'A' by using 'A-' for 'A'.
              str << char << '-'
            else
              str << char.ord
            end
          end
        end

        if @name.size > 50
          # 17 chars from name + 1 (dash) + 32 (md5) = 50
          @name = "#{@name[0..16]}-#{::Crystal::Digest::MD5.hexdigest(@name)}"
        end

        @name = "#{@name}#{@compiler.optimization_mode.suffix}"
        @object_extension = compiler.codegen_target.object_extension
      end

      def generate_bitcode
        @memory_buffer ||= llvm_mod.write_bitcode_to_memory_buffer
      end

      # To compile a file we first generate a `.bc` file and then create an
      # object file from it. These `.bc` files are stored in the cache
      # directory.
      #
      # On a next compilation of the same project, and if the compile flags
      # didn't change (a combination of the target triple, mcpu and link flags,
      # amongst others), we check if the new `.bc` file is exactly the same as
      # the old one. In that case the `.o` file will also be the same, so we
      # simply reuse the old one. Generating an `.o` file is what takes most
      # time.
      #
      # However, instead of directly generating the final `.o` file from the
      # `.bc` file, we generate it to a temporary name (`.o.tmp`) and then we
      # rename that file to `.o`. We do this because the compiler could be
      # interrupted while the `.o` file is being generated, leading to a
      # corrupted file that later would cause compilation issues. Moving a file
      # is an atomic operation so no corrupted `.o` file should be generated.
      def compile(isolate_context = false)
        if must_compile?
          isolate_module_context if isolate_context
          update_bitcode_cache
          compile_to_object
        else
          @reused_previous_compilation = true
        end
        dump_llvm_ir
      end

      private def must_compile?
        memory_buffer = generate_bitcode

        return true unless compiler.emit_targets.none?
        return true if @bc_flags_changed
        return true unless File.exists?(bc_name)
        return true unless File.exists?(object_name)

        # If the user cancelled a previous compilation
        # it might be that the .o file is empty
        return true if File.size(object_name) == 0

        memory_io = IO::Memory.new(memory_buffer.to_slice)

        changed = File.open(bc_name) { |bc_file| !IO.same_content?(bc_file, memory_io) }

        memory_buffer.dispose unless changed

        changed
      end

      # Parse the previously generated bitcode into the LLVM module using a
      # dedicated context, so we can safely optimize & compile the module in
      # multiple threads (llvm contexts can't be shared across threads).
      private def isolate_module_context
        @llvm_mod = LLVM::Module.parse(@memory_buffer.not_nil!, LLVM::Context.new)
      end

      private def update_bitcode_cache
        return unless memory_buffer = @memory_buffer

        # Delete existing .o file. It cannot be used anymore.
        File.delete?(object_name)
        # Create the .bc file (for next compilations)
        File.write(bc_name, memory_buffer.to_slice)
        memory_buffer.dispose
      end

      private def compile_to_object
        temporary_object_name = self.temporary_object_name
        target_machine = compiler.create_target_machine
        compiler.optimize llvm_mod, target_machine unless compiler.optimization_mode.o0?
        target_machine.emit_obj_to_file llvm_mod, temporary_object_name
        File.rename(temporary_object_name, object_name)
      end

      private def dump_llvm_ir
        llvm_mod.print_to_file ll_name if compiler.dump_ll?
      end

      def emit(emit_targets : EmitTarget, output_filename)
        if emit_targets.asm?
          compiler.target_machine.emit_asm_to_file llvm_mod, "#{output_filename}.s"
        end
        if emit_targets.llvm_bc?
          FileUtils.cp(bc_name, "#{output_filename}.bc")
        end
        if emit_targets.llvm_ir?
          llvm_mod.print_to_file "#{output_filename}.ll"
        end
        if emit_targets.obj?
          FileUtils.cp(object_name, output_filename + @object_extension)
        end
      end

      def object_name
        Crystal.relative_filename("#{@output_dir}/#{object_filename}")
      end

      def object_filename
        @name + @object_extension
      end

      def temporary_object_name
        Crystal.relative_filename("#{@output_dir}/#{object_filename}.tmp")
      end

      def bc_name
        "#{@output_dir}/#{@name}.bc"
      end

      def bc_name_new
        "#{@output_dir}/#{@name}.new.bc"
      end

      def ll_name
        "#{@output_dir}/#{@name}.ll"
      end
    end
  end
end
