# iyi: what it would take to put a Crystal shard behind an iyi boundary.
#
#   crystal tool bind -e Kemal shard_entry.cr
#
# R-2 asks every exported signature to write its types down, and Crystal infers
# instead of writing. Most of a shard's surface can be written down without a
# human: a method whose parameters carry types can be instantiated on purpose,
# and what it returns falls out of that. This says how much of a given shard is
# in that position, which is the number that decides whether a boundary is
# worth generating at all.
#
# It reads and counts; it writes no `.iyi` yet. Measuring first is the same
# order every other part of this project was built in.
#
# **It lives in the compiler rather than beside it**, and the reason is worth
# keeping: reading a shard means analysing the standard library it is written
# against, and the standard library asks `size_of`, which is answered from a
# data layout. A front end that links no LLVM has none, so a tool built that
# way cannot read a single real shard.
module Iyi
  # What a method is, for a boundary.
  enum BindVerdict
    # Every parameter and the return type are written. R-2 already.
    Ready
    # The parameters are written and the return type is not: a machine can
    # instantiate this and read the answer.
    NeedsReturn
    # A parameter carries no type. Nothing can guess it, so a human writes it.
    NeedsHuman
  end

  # What happened when a written return type was held against what a caller is
  # handed. III.6 rule 1 says the binding asserts and is not checked; this is
  # how much of that is still true, as a number rather than a sentence.
  enum BindCheck
    # Nothing was written, so there is nothing to check: what travels *is* what
    # instantiation answered, which is the half that was already checked.
    NotWritten
    # Written, instantiated, and the call answers what the restriction says.
    Agrees
    # Written, instantiated, and the call answers something else — `Int` where
    # a caller gets `Int32`, an abstract base where a factory hands back the
    # concrete class, a union with a member the method never produces. A
    # consumer told the written name is told something the symbol does not do.
    Disagrees
    # Written, and instantiation could not run. The restriction stands on the
    # shard's word, which is exactly what rule 1 describes.
    Unchecked
  end

  record BindMethod,
    owner : String,
    name : String,
    verdict : BindVerdict,
    block : Bool,
    untyped : Array(String),
    location : String,
    params : Array({String, String}),
    returns : String?,
    receiver : String,
    # The block parameter as written, `&block : Context -> B`, or empty.
    written_block : String,
    # What the return type turned out to be, once the method was instantiated
    # on purpose, or the reason it could not be.
    inferred : String?,
    refused : String?,
    # A generic's method travels as source, so the source has to be here.
    body : String?,
    # Whether every parameter names a type a variable can have. `Int` is a name
    # an iyi program can write and not a type anything can hold: it is the head
    # of a family, and a method taking one is compiled once per member with a
    # symbol apiece. The compiler answers this — `can_be_stored?` — and it is
    # the same answer that decides whether the generated keep file compiles.
    storable : Bool,
    # What holding the written return type against the call answered.
    checked : BindCheck,
    # What instantiation answered, when that differs from what was written —
    # and what travels, because the symbol is named after it.
    produced : String? do
    # What this method answers, which is not always what the shard wrote.
    #
    # The instantiated answer wins where the two disagree, and the linker is
    # what decided that rather than an argument. A shard writing
    # `def wider : String?` over a body returning a `String` gets a symbol named
    # `*Shard::Part#wider:String`; a declaration repeating the restriction has
    # the consumer ask for `*Shard::Part#wider:(String | Nil)`, and nobody
    # emitted one. `produced` is set only where they disagree, so this reads as
    # the written type everywhere else.
    def answer : String?
      produced || returns || inferred
    end

    # Every type this signature names, so the emitter can ask whether they can
    # all be named on the other side.
    def signature_types : Array(String)
      types = params.map { |(_, restriction)| restriction }
      if declared = answer
        types << declared
      end
      # The restriction only. `&block : Int32 -> Int32` names one type and one
      # parameter, and reading the parameter as a type made every annotated
      # block look like it mentioned something nobody declared.
      types << written_block.split(" : ", 2).last unless written_block.empty?
      types
    end

    # Whether anything outside could call this.
    #
    # A block-taking method is compiled per block *type* and the type is in the
    # symbol, so one whose block nobody annotated has no single symbol to
    # declare. `infer_return` already refuses these — but only when it runs, and
    # a method that writes its return type never reaches it. The keep file finds
    # the rest: `Time.measure` is expected to be invoked with a block.
    def callable? : Bool
      !block || !written_block.empty?
    end

    # The `pub def` an iyi module would carry. Parameters as the source wrote
    # them; the return from `answer`, which is what the source wrote only where
    # that is also what a caller is handed.
    def declaration : String
      args = params.map { |(name, restriction)| "#{name} : #{restriction}" }.join(", ")
      signature = args.empty? ? name : "#{name}(#{args})"
      "pub def #{signature} : #{answer || "Nil"}"
    end
  end

  # The types an iyi program already has, so a signature naming one of them
  # needs nothing from this boundary. Everything else is somebody's to declare,
  # and saying which is most of what a boundary costs.
  #
  # Asked of the program rather than written down here. The written-down version
  # claimed `Void`, `UInt32` and `Float64` — which iyi's prelude never declares —
  # and left out `Slice`, `Int`, `Tuple` and `NamedTuple`, which the compiler
  # creates for every program before any prelude is read. Those four were most
  # of what the boundary appeared to be waiting on, so the list was not merely
  # untidy: it invented the work it was being read to size.
  @@builtin = Set(String).new

  # The boundaries already written. A signature naming one of their types waits
  # on nobody: somebody has declared it, which is the whole question this asks.
  # `IO` is why this exists — it is what `JSON`, `YAML` and `URI` were all
  # waiting on, and once it has an artifact it stops being a gap.
  @@bound = Set(String).new

  # The types Crystal's library defines, which a consumer of a bound shard has.
  #
  # It has them because it must: the units number
  # `Pointer(LibUnwind::Exception)` whatever the shard does, so the consumer is
  # a `--crystal` program, and a `--crystal` program is one with Crystal's
  # library in it. The shard's own requires travel beside this, so the files the
  # prelude leaves out are there too.
  #
  # This predicate is what decides every count this tool prints, and it used to
  # ask what an *iyi-prelude* program could name — a program that cannot consume
  # one of these artifacts at all. So the surface read low: `Kemal::Route` and
  # five more were refused for naming types their actual consumer would have.
  @@crystal_types = Set(String).new

  # And what to call them from outside. A bound artifact's declarations sit
  # under the module the consumer imports, so `IO` is `Io::IO` there — the
  # producer's name is not the consumer's, and an artifact that referred to one
  # by the other resolved to nothing.
  @@bound_prefix = {} of String => String

  # Which module each of those names came from, and which of them this artifact
  # ended up naming. A boundary that refers to another one depends on it, and a
  # consumer should not have to work that out and write the `import` itself.
  @@bound_module = {} of String => String
  @@bound_used = Set(String).new

  # iyi: this scanner is reached by the compiler, so stdlib Regex would keep
  # pcre2 on its link line. Compile the grammar once through Iyi::Rx instead
  # of maintaining four hand-written tokenizers (SPEC.md III.10).
  private BIND_TYPE_NAME = Rx::Pattern.compile("[A-Za-z_][A-Za-z0-9_:]*")

  def self.print_bind(program : Program, root : String?, io : IO,
                      artifact_dir : String? = nil, bound_dir : String? = nil) : Nil
    unless root
      io.puts "tool bind needs the shard's own namespace: -e Kemal"
      return
    end

    @@builtin = program.builtin_type_names
    @@crystal_types = crystal_library_types program
    @@bound_prefix = {} of String => String
    @@mono_bodies = {} of String => String
    @@bound_module = {} of String => String
    @@bound_used = Set(String).new
    @@bound = bound_dir ? bound_names(program, bound_dir, io) : Set(String).new

    methods = [] of BindMethod
    collect_bind program.types?, root, methods

    ready = methods.count(&.verdict.ready?)
    inferable = methods.count(&.verdict.needs_return?)
    human = methods.count(&.verdict.needs_human?)

    io.puts "#{root}: #{methods.size} public methods on its own types"
    io.puts
    io.puts "  R-2 as written            #{ready}"
    io.puts "  a machine can write       #{inferable}"
    io.puts "  a human has to write      #{human}"
    io.puts
    io.puts "  of those, take a block    #{methods.count(&.block)}"

    machine = methods.select(&.verdict.needs_return?)
    unless machine.empty?
      answered = machine.count { |m| m.inferred }
      io.puts
      io.puts "instantiated on purpose, to read what they return:"
      io.puts "  answered                  #{answered}"
      io.puts "  refused                   #{machine.size - answered}"
      machine.select(&.refused).group_by { |m| m.refused.not_nil! }
        .to_a.sort_by { |(_, v)| -v.size }.first(8).each do |(reason, list)|
        io.puts "    %-38s %d" % [reason[0, 38], list.size]
      end
    end

    # III.6 rule 1 as a number. The half above reads a return nobody wrote; this
    # half holds a return somebody did write against the same answer, and says
    # how much of the boundary is still standing on the shard's word.
    written = methods.reject(&.checked.not_written?)
    unless written.empty?
      disagreed = written.select(&.checked.disagrees?)
      io.puts
      io.puts "written returns, held against what a caller is handed:"
      io.puts "  agrees                    #{written.count(&.checked.agrees?)}"
      io.puts "  disagrees                 #{disagreed.size}"
      io.puts "  could not be checked      #{written.count(&.checked.unchecked?)}"
      written.select { |m| m.checked.unchecked? && m.refused }
        .group_by { |m| m.refused.not_nil! }
        .to_a.sort_by { |(_, v)| -v.size }.first(8).each do |(reason, list)|
        io.puts "    %-38s %d" % [reason[0, 38], list.size]
      end

      unless disagreed.empty?
        io.puts
        io.puts "  and the ones that travel as the answer, not as written:"
        disagreed.sort_by { |m| {m.owner, m.name} }.first(12).each do |method|
          io.puts "    #{method.owner}##{method.name}"
          io.puts "      writes #{method.returns}, answers #{method.produced}"
        end
        io.puts "    ... and #{disagreed.size - 12} more" if disagreed.size > 12
      end
    end

    return if methods.empty?
    mechanical = ready + inferable
    io.puts
    io.puts "  #{(mechanical * 100.0 / methods.size).round(1)}% of the surface needs no human."

    emit_module program, methods, root, io
    write_artifact program, methods, root, artifact_dir, io if artifact_dir

    return if human.zero?

    # Named, because the count is the estimate and this is the work. Each line
    # is one signature somebody has to decide, and the parameter it is about.
    io.puts
    io.puts "what a human has to write:"
    methods.select(&.verdict.needs_human?).sort_by { |m| {m.owner, m.name} }.each do |method|
      io.puts "  #{method.owner}##{method.name}(#{method.untyped.join(", ")})"
      io.puts "    #{method.location}"
    end
  end

  # The draft boundary: what a consumer would import.
  #
  # A signature goes in when every type in it is one an iyi program can name —
  # the shard's own, or the prelude's. What is left out is left out by name,
  # because those are the types somebody has to decide about, and deciding is
  # the work this tool exists to size.
  private def self.emit_module(program : Program, methods : Array(BindMethod),
                               root : String, io : IO) : Nil
    known = methods.select { |m| m.verdict.ready? || m.inferred }
    lines = [] of String
    outside = Hash(String, Int32).new(0)
    unnameable = Hash(String, Int32).new(0)

    unheld = 0
    unblocked = 0
    waiting = 0
    never = 0
    known.each do |method|
      types = method.signature_types
      foreign = types.reject { |t| nameable?(t, root) }
      unless method.storable
        unheld += 1
        next
      end
      unless method.callable?
        unblocked += 1
        next
      end
      if foreign.empty?
        lines << method.declaration
      else
        # Whether anything on this signature is a type somebody could declare.
        # If nothing is, no amount of work reaches it and it does not belong in
        # the same count as the ones that are waiting for a decision.
        declarable = false
        # Named by the part that is missing rather than by the whole
        # signature, because the part is what somebody has to declare and one
        # decision unblocks every signature that mentions it.
        foreign.each do |type|
          Rx.scan(type, BIND_TYPE_NAME).each do |match|
            part = match[0].not_nil!
            next if part == "class"
            next if nameable_name?(part, root)
            # `T` is a free variable, `self` is the receiver and `_` is a block
            # nobody annotated. None is a type anybody could declare, and
            # counting them beside `IO` said there was more waiting than there
            # was — the same inflation, one layer further in.
            if declared_type? program, part
              outside[part] += 1
              declarable = true
            else
              unnameable[part] += 1
            end
          end
        end
        declarable ? (waiting += 1) : (never += 1)
      end
    end

    io.puts
    io.puts "a boundary this tool can already write:"
    io.puts "  signatures                #{lines.size}"
    io.puts "  waiting on a type nobody has declared  #{waiting}"
    if unheld > 0
      io.puts "  taking a type no variable can hold     #{unheld}"
    end
    if never > 0
      io.puts "  naming something that is not a type    #{never}"
    end
    if unblocked > 0
      io.puts "  taking a block nobody annotated        #{unblocked}"
    end

    unless outside.empty?
      io.puts
      io.puts "the types that boundary is waiting on:"
      outside.to_a.sort_by { |(_, c)| -c }.first(10).each do |(name, count)|
        io.puts "  %-44s %d" % [name, count]
      end
    end

    unless unnameable.empty?
      io.puts
      io.puts "and the names that are not types anybody can declare:"
      unnameable.to_a.sort_by { |(_, c)| -c }.first(10).each do |(name, count)|
        io.puts "  %-44s %d" % [name, count]
      end
      io.puts "  A free variable, `self`, or a block nobody annotated. These"
      io.puts "  never cross, and no work makes them."
    end

    # Only the ones a declaration would actually free. A signature this tool
    # refuses for its parameters or its block is not waiting on anybody, and
    # counting it here would promise that declaring a type reaches it.
    blockable = known.select { |method| method.storable && method.callable? }
    unlocked = blocked_by(program, blockable, root)
    unless unlocked.empty?
      io.puts
      io.puts "declaring one type at a time, and what each one unlocks:"
      declared = Set(String).new
      total = 0
      unlocked.first(8).each do |name|
        declared << name
        opened = blockable.count do |method|
          foreign_names(method, root).all? { |t| declared.includes?(t) } &&
            !foreign_names(method, root).empty?
        end
        io.puts "  %-40s %+d  (%d in all)" % [name, opened - total, opened]
        total = opened
      end
    end

    return if lines.empty?

    io.puts
    io.puts "# --- draft ---"
    io.puts "# Flat, and a real boundary is not: these methods belong to the"
    io.puts "# types that declare them, and grouping them there is the next"
    io.puts "# thing this tool has to learn. What is settled here is the part"
    io.puts "# that was in doubt, which is whether the signatures can be known."
    io.puts "module #{iyi_module_name(root)}"
    io.puts
    lines.sort.each { |line| io.puts line }
    io.puts "# --- end ---"
  end

  # The artifact itself: declarations a consumer type-checks against.
  #
  # There is nothing new in it. The two sides mangle names identically, being
  # one compiler — `Lib::Greeter.polite(String) : String` is
  # `*Lib::Greeter@Lib::Greeter::polite<String>:String` compiled from either
  # language — so a shard's object file already defines the symbols an iyi
  # consumer would call. What was missing was a `.iyimod` saying they exist.
  #
  # Module functions only for now, which is the shape that was proved end to
  # end. A method on a type needs a `TypeDecl` beside it, and that is the next
  # thing this has to learn.
  private def self.write_artifact(program : Program, methods : Array(BindMethod),
                                  root : String, dir : String, io : IO) : Nil
    # Both spellings of "on the module itself". A module written with
    # `extend self` — which is what an iyi module header desugars to, and what
    # a Crystal library writes by hand for the same reason — defines its
    # functions on the module and reaches them through the metaclass, so the
    # owner recorded here is one or the other depending on which side wrote it.
    owners = {root, "#{root}:Module"}
    signatures = [] of IyiMod::Signature
    seen = Set(String).new

    # And only a module has them. `Kemal.run` is a module function because
    # `Kemal` is a module and its own methods are reachable through it; `IO`'s
    # are not — `IO.write` is an instance method and calling it on the class is
    # an error. A class root's own surface has to travel as *its type's*
    # methods, which is work this tool has not done, so it travels as nothing
    # rather than as a declaration naming a symbol nobody emits.
    methods.each do |method|
      next unless module_root? program, root
      next unless owners.includes?(method.owner)
      next unless seen.add?(method.name)
      next unless method.verdict.ready? || method.inferred
      next unless method.storable
      next unless method.callable?
      next unless method.signature_types.all? { |t| nameable?(t, root) }

      signatures << IyiMod::Signature.new(
        name: method.name,
        # Whose method it is, which the symbol carries. A module written
        # `extend self` defines `polite` on the module and mangles
        # `*Widget@Widget::polite<String>:String`; one written `def self.polite`
        # defines it on the metaclass and mangles `*Widget::polite<String>:String`
        # — no `@`. Both were recorded as the first, so every `def self.` in a
        # shard produced a declaration the consumer called by a name nothing
        # emitted. Crystal's own library is written the second way throughout.
        receiver: method.owner == "#{root}:Module" && method.receiver.empty? ? "self" : method.receiver,
        parameters: method.params.map { |(name, restriction)| "#{name} : #{restriction}" },
        block_parameter: method.written_block,
        return_type: method.answer.not_nil!,
        free_variables: [] of String,
        required: false,
      )
    end

    types = type_declarations program, methods, root

    # A constant crosses as a function, and that function gets an iyi module
    # function's symbol from `extend self` — which only a module takes. So a
    # class root's constants stay behind rather than being declared with
    # nothing to link against, a failure that is invisible until link time.
    accessors =
      if module_root? program, root
        constant_accessors program, root, types
      else
        [] of {IyiMod::Signature, String}
      end

    signatures.concat accessors.map(&.[0])

    # An artifact's declarations belong to the artifact, not to the namespace
    # that produced them.
    #
    # A class root already reads that way: its own name is a declaration in the
    # file, so `MySink::Entry` resolves wherever the module lands. A module root
    # dropped that name and kept the references — `MyLib::Entry` with no `MyLib`
    # — and the consumer cannot supply it, because an iyi module path is
    # `[a-z][a-z0-9]*` and its mapping to a type name is deliberately reversible
    # (IV.6 #6). `MyLib` comes back as `Mylib`, and `JSON` is not in the image of
    # that mapping at all. So the producer's prefix comes off instead.
    #
    # Into copies, and that is the whole of the care this needs. The keep file
    # below is *Crystal*, compiled against the shard where these names are the
    # shard's own: renaming there produces `undefined constant Any` and no
    # object file at all.
    exported = signatures
    carried_types = types
    if module_root? program, root
      exported = exported.map { |signature| strip_root signature, root }
      carried_types = carried_types.map { |declaration| strip_root_declaration declaration, root }
    end

    # And a reference to somebody else's boundary is written the way the
    # consumer will see it.
    unless @@bound_prefix.empty?
      exported = exported.map { |signature| map_names signature }
      carried_types = carried_types.map { |declaration| map_names_declaration declaration }
    end

    artifact = IyiMod::Artifact.new(
      module_name: iyi_module_name(root),
      # The shard's own constants, as the assignments that make them.
      #
      # A constant travels by *name* so that its initialiser runs once, in the
      # program that will read it — but a name is only half of it, and the half
      # a bound shard was missing. Its unit refers to `Store::TABLE` and defines
      # nothing; the consumer had the name from `Constants` and no way to make
      # one, so it said `undefined constant ::Store::TABLE` and stopped.
      #
      # The text goes in the initialiser, which the reader renders last and
      # inside the module — so `TABLE = [...]` under `module store` is
      # `Store::TABLE`, in the namespace the shard wrote it in, built by the
      # consumer's own program at the time III.5 says.
      initialiser: constant_source(program, root),
      source_path: program.filename || "",
      compiler_version: IyiMod.compiler_version,
      target_triple: program.codegen_target.to_s,
      flags: program.flags.to_a.sort!,
      imports: @@bound_used.to_a.sort.map { |name| IyiMod::ImportEdge.new(name) },
      mono_bodies: @@mono_bodies.dup,
      requires: crystal_requires(program),
      exports: IyiMod::Exports.new(exported, carried_types, [] of IyiMod::ImplRecord),
      # True, and it was false here on an argument that measurement has since
      # answered. The argument was that a boundary stands *between* Crystal's
      # library and the consumer, so what crosses is handles and primitives and
      # the consumer is an ordinary iyi program. What crosses is not: the unit
      # this artifact carries is compiled under Crystal's library and numbers
      # `Pointer(LibUnwind::Exception)` whatever the shard does, because a
      # `String#+` can raise. An iyi program cannot name that type, and telling
      # it the artifact is one of its own only moved the refusal later.
      crystal_library: true,
    )

    path = File.join(dir, "#{iyi_module_name(root).gsub('/', '-')}.iyimod")
    IyiMod.write artifact, path

    keep_path = File.join(dir, "#{iyi_module_name(root).gsub('/', '-')}_keep.cr")
    File.write keep_path, keep_file(program, root, signatures, types, accessors, dir)

    io.puts
    carried = count_methods types
    unless @@handle_types.empty?
      io.puts
      io.puts "crossed as handles, without their fields: #{@@handle_types.size}"
      io.puts "  a reference is a pointer, so a consumer that never allocates"
      io.puts "  one does not need to know what is inside it. `new` is not"
      io.puts "  exported for these, which is what keeps that true."
    end

    unless module_root? program, root
      kind = program.types?.try(&.[]?(root)).try(&.instance_type.type_desc) || "type"
      io.puts
      io.puts "#{root} is a #{kind}, so it travels as a type declaration holding"
      io.puts "everything under it, rather than as module functions. Its constants"
      io.puts "stay behind: a constant crosses as a function, and that function"
      io.puts "takes its symbol from `extend self`, which only a module has."
    end

    unless @@skipped_enums.empty?
      io.puts
      io.puts "enums, which iyi does not have: #{@@skipped_enums.uniq!.sort!.join(", ")}"
      io.puts "  Nothing declares one on the far side, so a signature naming one"
      io.puts "  cannot cross and neither can a type holding one. This is what"
      io.puts "  `JSON` waits on, through `JSON::PullParser`."
    end

    unless @@nested_namespaces.empty?
      io.puts
      io.puts "namespaces skipped whole: #{@@nested_namespaces.uniq!.sort!.join(", ")}"
      io.puts "  what they hold has to travel as nested declarations."
    end

    unless @@opaque_types.empty?
      io.puts
      io.puts "left out, because their fields name what an iyi program cannot:"
      @@opaque_types.sort.first(12).each { |name| io.puts "  #{root}::#{name}" }
      if @@opaque_types.size > 12
        io.puts "  ... and #{@@opaque_types.size - 12} more"
      end
      io.puts
      io.puts "These are the per-type decisions a boundary is made of. A type"
      io.puts "the consumer only holds can cross as a handle; one it allocates"
      io.puts "needs its fields, and its fields need their types."
    end

    io.puts "wrote #{path}: #{signatures.size} module functions, " \
            "#{count_types types} types carrying #{carried} methods"
    io.puts "wrote #{keep_path}"
    io.puts
    unless round_trips? root
      seen_as = consumer_name root
      io.puts
      io.puts "#{root} cannot be linked against, and this is the place to say so."
      io.puts "  An iyi module path is lower-case groups joined by `_`, and a"
      io.puts "  consumer names the module by camelcasing it. That mapping's image"
      io.puts "  is names like `Greeter` and `MyGreeter`; `#{root}` is not in it — it"
      io.puts "  comes back as `#{seen_as}`. Both sides mangle alike, so the producer"
      io.puts "  emits `*#{root}@#{root}::...` while the consumer asks for"
      io.puts "  `*#{seen_as}@#{seen_as}::...`, and the linker is what finds out."
      io.puts
      io.puts "  The declarations below are still true and still worth counting."
      io.puts "  What cannot happen is the last of the four steps."
      io.puts
    end

    io.puts "The artifact carries declarations and no object code yet, because"
    io.puts "the code does not exist: Crystal compiles what a program uses, and a"
    io.puts "library nobody calls compiles to nothing. The keep file above is what"
    io.puts "calls it. Two commands finish the boundary:"
    io.puts
    io.puts "  crystal build --iyi-keep #{root} --emit-bind #{dir} -o keepbin #{keep_path}"
    io.puts "  iyi build --crystal --use-iyimod #{dir} -o app app.iyi"
    io.puts
    io.puts "An *ordinary* build on the first line, not `--emit obj`. Codegen"
    io.puts "splits a program into one object per type, and the ones #{root} owns"
    io.puts "carry no runtime; `--emit obj` merges them into a single object that"
    io.puts "carries the whole of Crystal's library with it. A program can have"
    io.puts "that library once — link the merged object into a consumer that has"
    io.puts "none and the shard's constants never initialise, link it into one"
    io.puts "that has it and every runtime global is defined twice. `--emit-bind`"
    io.puts "puts the per-type units in the artifact instead, and the consumer"
    io.puts "links what the artifact carries. No `nm` and no `objcopy`."
    io.puts
    io.puts "`--crystal` on the second line is not decoration either. This unit"
    io.puts "numbers `Pointer(LibUnwind::Exception)` whatever #{root} does, because"
    io.puts "a `String#+` can raise, and an iyi program cannot name that type."
    io.puts
    io.puts "A constant crosses as the assignment that makes it, so the consumer"
    io.puts "builds it in its own program at the time III.5 says. That is what a"
    io.puts "unit needs: it refers to `#{root}::SOMETHING` and defines nothing."
    io.puts "A constant the compiler folds never needed this; one built at run"
    io.puts "time did, and used to read as null and segfault."
    io.puts "One inside a type under #{root} crosses too, written `Inner::X = ...`,"
    io.puts "which defines rather than reopens wherever the namespace exists — and"
    io.puts "the declarations above this text are what make it exist."
    io.puts
    io.puts "`--iyi-keep` is not decoration: a getter whose body is one instance"
    io.puts "variable is inlined at every call site and emits no symbol, which"
    io.puts "is right for a whole program and wrong for code somebody else will"
    io.puts "call by name. The symbols are local until that `objcopy`, and"
    io.puts "global is what a consumer links against. Nothing here goes through"
    io.puts "a C ABI: the two sides are one compiler and mangle names alike."
  end

  # The way to a shard's objects, which is the thing a boundary was missing.
  #
  # A library hands out what it has through constants — `Config::INSTANCE`,
  # one handler apiece — and a constant is storage in the shard's own object
  # rather than something a declaration can name. A function is not: it crosses
  # like any other. So this writes one per constant, on the shard's own module,
  # and the artifact declares it.
  #
  # `Kemal::Config::INSTANCE` becomes `Kemal.config_instance`, which is a name
  # a consumer can guess from the constant's own.
  private def self.constant_accessors(program : Program, root : String,
                                      types : Array(IyiMod::TypeDecl)) : Array({IyiMod::Signature, String})
    known = Set(String).new
    types.each { |declaration| collect_known declaration, "#{root}::", known }

    accessors = [] of {IyiMod::Signature, String}
    root_type = program.types?.try &.[]?(root)
    return accessors unless root_type.is_a?(NamedType)

    collect_constants root_type, root, "", known, accessors
    accessors
  end

  private def self.collect_constants(owner : NamedType, root : String, prefix : String,
                                     known : Set(String),
                                     accessors : Array({IyiMod::Signature, String})) : Nil
    owner.types?.try &.each do |name, type|
      case type
      when Const
        # A private constant cannot be handed out: an accessor reads it, and
        # reading one from outside is what its own compiler refuses. It still
        # travels in the initialiser, because *defining* it is not *reading* it
        # and the object code refers to it either way.
        next if type.private?
        answer = type.value.type?
        next unless answer

        answer = global_name(answer.devirtualize.to_s, root)
        next unless nameable?(answer, root)
        # Only a type that travelled: a name under the shard's own namespace is
        # writable only if the artifact carries it.
        next unless answer == root || !answer.starts_with?("#{root}::") || known.includes?(answer)

        accessor = "#{prefix}#{name}".downcase
        constant = "#{root}::#{prefix.gsub("_", "::")}#{name}"
        constant = "#{root}::#{name}" if prefix.empty?

        accessors << {
          IyiMod::Signature.new(
            name: accessor,
            receiver: "",
            parameters: [] of String,
            block_parameter: "",
            return_type: answer,
            free_variables: [] of String,
            required: false,
          ),
          constant,
        }
      when NamedType
        next if type.is_a?(GenericType)
        # An enum's members are `Const`s and are not constants to hand out:
        # they travel with the enum, and an accessor for one names the enum
        # from outside — which for a private enum is what the shard's own
        # compiler refuses (`private constant ... referenced`).
        next if type.is_a?(EnumType)
        next if type.private?
        collect_constants type, root, "#{prefix}#{name}_", known, accessors
      end
    end
  end

  # The types the shard declares, with the methods that can be written down.
  #
  # A method on a type is where most of a shard's surface lives, and it is the
  # half that could not travel while an artifact carried module functions
  # alone. What a consumer needs is what `TypeDecl` already asks for: the name,
  # the kind, the fields — a consumer allocates the type and allocating needs
  # its size — and the signatures.
  #
  # Non-generic only. A generic's methods exist once per instantiation and have
  # no symbol a producer could have emitted, so they travel as bodies rather
  # than as declarations (IV.2), and that is a different piece of work.
  # The types whose fields name something an iyi program cannot, filled in by
  # `type_declarations` and reported beside the artifact it wrote.
  @@opaque_types = [] of String

  # The reference types that crossed without their fields: a consumer holds one
  # and calls through it, and never makes one.
  @@handle_types = [] of String

  # The namespaces skipped whole, with whatever they hold.
  @@nested_namespaces = [] of String

  # And the enums, which are skipped for a different reason worth its own line.
  @@skipped_enums = [] of String

  private def self.type_declarations(program : Program, methods : Array(BindMethod),
                                     root : String) : Array(IyiMod::TypeDecl)
    by_owner = methods.group_by(&.owner)
    declarations = [] of IyiMod::TypeDecl

    root_type = program.types?.try &.[]?(root)
    return declarations unless root_type.is_a?(NamedType)

    if module_root? program, root
      collect_declarations root_type, by_owner, root, declarations
      prune_dangling declarations, "#{root}::", root
    else
      # A class root's own methods are its type's rather than module functions,
      # so it travels as one declaration holding everything under it. The names
      # inside are then already absolute — `IO`, `IO::Memory` — which is why the
      # prefix the pruner resolves against is empty here and `IO::` there.
      declaration = declaration_for root, root_type, by_owner, root
      declarations << declaration if declaration
      prune_dangling declarations, "", root
    end
  end

  # Nothing may name a type that did not travel.
  #
  # `nameable?` answers "could an iyi program write this name", and for a type
  # under the shard's own namespace it used to answer yes on the strength of
  # the name alone. That is true only if the type is *here*: `Kemal::Router`
  # holds an `Array(Kemal::Router::RouteDefinition)` and that record is a
  # struct whose fields name `HTTP::Server::Context`, so it stays behind and
  # the artifact named a constant nobody had. Repeated to a fixed point,
  # because dropping one type can strand the field that named it.
  private def self.prune_dangling(declarations : Array(IyiMod::TypeDecl),
                                  prefix : String, root : String) : Array(IyiMod::TypeDecl)
    loop do
      known = Set(String).new
      declarations.each { |declaration| collect_known declaration, prefix, known }

      pruned = [] of IyiMod::TypeDecl
      declarations.each do |declaration|
        kept = prune_declaration declaration, prefix, known, root
        pruned << kept if kept
      end

      break declarations if pruned.size == declarations.size &&
                            pruned.sum(&.methods.size) == declarations.sum(&.methods.size) &&
                            pruned.sum(&.fields.size) == declarations.sum(&.fields.size)
      declarations = pruned
    end
  end

  private def self.collect_known(declaration : IyiMod::TypeDecl, prefix : String,
                                 known : Set(String)) : Nil
    known << "#{prefix}#{declaration.name}"
    declaration.types.each do |nested|
      collect_known nested, "#{prefix}#{declaration.name}::", known
    end
  end

  private def self.prune_declaration(declaration : IyiMod::TypeDecl, prefix : String,
                                     known : Set(String), root : String) : IyiMod::TypeDecl?
    resolvable = ->(text : String) do
      Rx.scan(text, BIND_TYPE_NAME).all? do |match|
        part = match[0].not_nil!
        next true if part == "class"
        next true unless part == root || part.starts_with?("#{root}::")
        known.includes?(part)
      end
    end

    fields = declaration.fields.select { |(_, type_name)| resolvable.call(type_name) }
    if fields.size != declaration.fields.size
      # A struct is its fields, so one that cannot carry them cannot travel.
      return nil unless declaration.kind == "class"
      fields = [] of {String, String}
    end

    methods = declaration.methods.select do |signature|
      (signature.parameters + [signature.return_type]).all? { |text| resolvable.call(text) }
    end
    methods = methods.reject { |signature| signature.name == "new" } if fields.empty? && !declaration.fields.empty?

    nested = [] of IyiMod::TypeDecl
    declaration.types.each do |child|
      kept = prune_declaration child, "#{prefix}#{declaration.name}::", known, root
      nested << kept if kept
    end

    IyiMod::TypeDecl.new(
      name: declaration.name,
      kind: declaration.kind,
      type_parameters: declaration.type_parameters,
      assoc_types: declaration.assoc_types,
      supertraits: declaration.supertraits,
      fields: fields,
      methods: methods,
      visibility: declaration.visibility,
      types: nested,
      # Everything a rebuild has to carry forward. Dropped here once, which is
      # how an alias lost its right-hand side and an enum its members: a pruner
      # that reconstructs a declaration has to reconstruct all of it.
      value: declaration.value,
      macros: declaration.macros,
      members: declaration.members,
    )
  end

  # One level, and then the level under it.
  #
  # A nested type is not a detail: `Kemal::Router` holds an
  # `Array(Kemal::Router::RouteDefinition)`, so a consumer that has the first
  # and not the second cannot read the field it was given. `TypeDecl` carries
  # nested declarations for exactly this, and a walk that stopped at the top
  # produced an artifact naming a constant nobody had.
  private def self.collect_declarations(owner_type : NamedType, by_owner, root : String,
                                        declarations : Array(IyiMod::TypeDecl)) : Nil
    owner_type.types?.try &.each do |name, type|
      declaration = declaration_for name, type, by_owner, root
      declarations << declaration if declaration
    end
  end

  # One type, as a declaration — or nil, for the several reasons one cannot be.
  #
  # Split out from the walk above because the root itself needs the same answer.
  # A shard's root is a module and its own methods travel as module functions;
  # a core type's root is a class, whose methods are its type's and have to
  # travel here.
  private def self.declaration_for(name : String, type : Type, by_owner,
                                   root : String) : IyiMod::TypeDecl?
    # A constant lives in the same table as a type — `Kemal::VERSION` is in
    # here — and asking one for its instance variables is how this found out.
    return nil unless type.is_a?(ModuleType)

    # A generic travels as a declaration *and* its bodies. Its methods exist
    # once per instantiation and the instantiations belong to whoever writes
    # them — a consumer that writes `Holder(Float64)` needs a method the
    # producer never made — so what crosses is the source, rendered back into
    # the declarations the consumer parses (IV.2, `MonoBodies`). Skipping them
    # is what left `Radix` with nothing to carry, and `Radix` is what `Kemal`
    # waits on.
    if type.is_a?(GenericClassType)
      return generic_declaration name, type, by_owner, root
    end
    return nil if type.is_a?(GenericType)
    # A private type travels *as private*, which is a different thing from
    # travelling and a different thing from being dropped.
    #
    # Dropped was the first answer and it is wrong for a reason only the linker
    # says: `JSON::PullParser` holds an `Array(ObjectStackKind)` and its object
    # code numbers `Pointer(ObjectStackKind)`, so the consumer has to be able to
    # *number* a type it must never be able to *write*. Declaring it without
    # `pub` gives exactly that — R-2b keeps the name unreachable, and the type id
    # the object file needs exists. What must not happen is the keep file naming
    # it, which is where dropping it came from: `private constant IO::Encoder
    # referenced`. `keep_type` skips these instead.
    private_type = type.private?

    # `pub` takes a def, a class, a struct and a trait — not a module, which
    # is what a nested namespace like `Kemal::Exceptions` is. What it holds
    # has to travel as its own nested declarations, and this walk does not go
    # there yet.
    # An enum travels as itself: its members and the integer it is written on.
    #
    # It was skipped once and reported as a "namespace skipped whole", on the
    # reasoning that iyi has no `enum` — which came from finding none in the
    # prelude and was wrong about the language, which takes one. `JSON` is what
    # this was costing: `JSON::PullParser` holds an `ObjectStackKind`.
    if type.is_a?(EnumType)
      return enum_declaration name, type, private_type
    end

    unless type.is_a?(ClassType)
      @@nested_namespaces << name
      return nil
    end

    begin
      signatures = [] of IyiMod::Signature
      {% begin %}{% end %}
      { {type.to_s, false}, {type.metaclass.to_s, true} }.each do |(owner, on_metaclass)|
        by_owner[owner]?.try &.each do |method|
          next unless method.verdict.ready? || method.inferred
          next unless method.storable
          next unless method.callable?
          next unless method.signature_types.all? { |t| nameable?(t, root) }

          signatures << IyiMod::Signature.new(
            name: method.name,
            # `new` is synthesized from `initialize` and carries no receiver of
            # its own, so a class method would arrive on the far side as an
            # instance method with the right name and the wrong reach.
            receiver: on_metaclass && method.receiver.empty? ? "self" : method.receiver,
            parameters: method.params.map { |(argument, restriction)| "#{argument} : #{restriction}" },
            block_parameter: method.written_block,
            return_type: method.answer.not_nil!,
            free_variables: [] of String,
            required: false,
          )
        end
      end

      fields = [] of {String, String}
      if type.is_a?(InstanceVarContainer)
        type.instance_vars.each do |field, variable|
          # Devirtualised, for the reason `infer_return` gives: `IO+` is how a
          # virtual type prints and it is a fact about this build's dispatch
          # rather than a name anybody can write. A field declared `IO+` is a
          # field nobody can read back.
          fields << {field, variable.type?.try(&.devirtualize.to_s) || "?"}
        end
      end

      # A field is not optional the way a method is. A consumer allocates the
      # type, and allocating needs its size, so a type whose fields name the
      # standard library cannot cross as a declaration at all — it can only
      # cross as a handle the consumer never allocates, which is a decision
      # somebody has to make per type rather than a gap a tool can close.
      foreign_fields = fields.map { |(_, type_name)| type_name }
        .reject { |type_name| nameable?(type_name, root) }

      # A reference type is a pointer to the consumer, so it can cross without
      # its fields as long as the consumer never allocates one: it holds what
      # the shard handed it and calls methods through it. A struct cannot —
      # its size *is* its fields — so one whose fields name the standard
      # library stays behind.
      handle = !foreign_fields.empty?
      if handle
        unless type.is_a?(ClassType) && !type.struct?
          @@opaque_types << name
          return nil
        end

        fields = [] of {String, String}
        signatures.reject! { |signature| signature.name == "new" }
        @@handle_types << name
      end

      nested = [] of IyiMod::TypeDecl
      collect_declarations type, by_owner, root, nested

      IyiMod::TypeDecl.new(
        name: name,
        kind: type.type_desc,
        type_parameters: [] of String,
        assoc_types: [] of String,
        supertraits: [] of String,
        fields: fields,
        methods: signatures.sort_by(&.name),
        visibility: private_type ? "private" : "pub",
        types: nested,
      )
    end
  end

  # A method has as many symbols as it has ways of being called, and this emits
  # one call for each of them.
  #
  # The mangled name carries the types at the *call site*, not the types in the
  # declaration. `JSON.parse(input : String | IO)` is one declaration and at
  # least three symbols: a consumer passing a string reaches
  # `*JSON::parse<String>:JSON::Any`, one passing an `IO` reaches `<IO+>`, and
  # one passing a variable of the declared union reaches `<(IO+ | String)>`.
  # Naming only the last is what this file did, so every consumer that passed a
  # plain string linked against nothing.
  #
  # The product of the parameters' shapes, which sounds worse than it measures:
  # a union parameter is about one in twenty — 7 of `IO`'s 103, 1 of `JSON`'s 53
  # — so two in one signature is rare and the product stays small. `KEEP_CALL_CAP`
  # is there for when it is not, and it says so rather than quietly emitting the
  # declared shape alone.
  KEEP_CALL_CAP = 16

  private def self.keep_call(io : IO, target : String, signature : IyiMod::Signature,
                             counter : Int32) : Int32
    declared = signature.parameters.map { |parameter| parameter.split(" : ").last }
    shapes = declared.map { |type| [type] + union_members(type) }

    combinations = shapes.reduce([[] of String]) do |carried, options|
      carried.flat_map { |prefix| options.map { |option| prefix + [option] } }
    end

    if combinations.size > KEEP_CALL_CAP
      @@capped << "#{target}.#{signature.name}"
      combinations = [declared]
    end

    combinations.each do |types|
      counter = keep_one_call(io, target, signature, types, counter)
    end
    counter
  end

  # The signatures whose shapes outran the cap, reported beside the artifact.
  @@capped = [] of String

  # `(A | B)` as `["A", "B"]`, and anything else as `[]`. Split at the top level
  # only: `(Array(A | B) | C)` is two members, not three.
  private def self.union_members(type : String) : Array(String)
    body = type.strip
    return [] of String unless body.starts_with?('(') && body.ends_with?(')')
    body = body[1...-1]

    members = [] of String
    depth = 0
    current = String::Builder.new
    body.each_char do |char|
      case char
      when '(' then depth += 1; current << char
      when ')' then depth -= 1; current << char
      when '|'
        if depth.zero?
          members << current.to_s.strip
          current = String::Builder.new
        else
          current << char
        end
      else current << char
      end
    end
    members << current.to_s.strip
    members.size > 1 ? members.reject(&.empty?) : [] of String
  end

  private def self.keep_one_call(io : IO, target : String, signature : IyiMod::Signature,
                                 types : Array(String), counter : Int32) : Int32
    args = types.map do |type|
      name = "a#{counter}"
      counter += 1
      io << "  " << name << " = uninitialized " << type << "\n"
      name
    end
    io << "  " << target << "." << signature.name
    io << "(" << args.join(", ") << ")" unless args.empty?

    # A block-taking method is compiled per block *type*, and the type is in
    # the symbol: `twice<Int32, &Proc(Int32, Int32)>`. So one is emitted here
    # by passing a block of the annotated type, and every consumer that writes
    # a block of that type calls the same name. A block whose output is `_` has
    # no annotated type and no single symbol, which is why it never got here.
    unless signature.block_parameter.empty?
      inputs, output = block_shape signature.block_parameter
      names = inputs.map_with_index { |_, index| "b#{counter + index}" }
      counter += inputs.size
      io << " { "
      io << "|" << names.join(", ") << "| " unless names.empty?
      if output.empty? || output == "Nil"
        io << "nil"
      else
        io << "r#{counter} = uninitialized " << output << "; r#{counter}"
        counter += 1
      end
      io << " }"
    end

    io << "\n"
    counter
  end

  # `&block : Int32, String -> Bool` read as its inputs and its output.
  private def self.block_shape(written : String) : {Array(String), String}
    restriction = written.split(" : ", 2).last.strip.lchop('(').rchop(')')
    head, _, tail = restriction.partition("->")
    inputs = head.split(',').map(&.strip).reject(&.empty?)
    {inputs, tail.strip}
  end

  # A file that calls everything and is never called.
  #
  # Codegen is demand-driven, which is right for a program and wrong for a
  # library: the shard's own build emits only what its own code reaches, so a
  # method a *consumer* will call is in no object file at all. Naming them here
  # is what puts them there.
  private def self.keep_file(program : Program, root : String,
                             signatures : Array(IyiMod::Signature),
                             types : Array(IyiMod::TypeDecl),
                             accessors : Array({IyiMod::Signature, String}),
                             dir : String) : String
    # Relative, and written from where this file will sit: Crystal refuses an
    # absolute path in a `require`, and the shard is not on `IYI_PATH`.
    source = ::Path[File.expand_path(program.filename || "")]
    base = ::Path[File.expand_path(dir)]
    relative = source.relative_to?(base).try(&.to_s) || source.to_s
    relative = "./#{relative}" unless relative.starts_with?(".")

    String.build do |io|
      io << "# Written by `crystal tool bind`. Never called, and never edited:\n"
      io << "# it exists so that codegen emits the methods a consumer will call.\n"
      io << "require \"" << relative << "\"\n\n"
      unless accessors.empty?
        io << "# One function per constant the shard hands its objects out\n"
        io << "# through. A constant is storage; a function crosses.\n"
        io << "#\n"
        io << "# `extend self` rather than `def self.`, because that is what an\n"
        io << "# iyi module header desugars to and the two have to agree on the\n"
        io << "# symbol: one writes `Kemal@Kemal::x`, the other `Kemal::x`.\n"
        io << "module " << root << "\n"
        io << "  extend self\n\n"
        accessors.each do |(signature, constant)|
          io << "  def " << signature.name << " : " << signature.return_type << "\n"
          io << "    " << constant << "\n"
          io << "  end\n"
        end
        io << "end\n\n"
      end

      io << "fun __bind_keep : Nil\n"
      counter = 0
      signatures.each do |signature|
        counter = keep_call(io, root, signature, counter)
      end
      accessors.each do |(signature, _)|
        io << "  " << root << "." << signature.name << "\n"
      end
      prefix = module_root?(program, root) ? "#{root}::" : ""
      types.each do |declaration|
        counter = keep_type io, prefix, declaration, counter
      end
      io << "end\n"
    end
  end

  # Whether the root is a module, which decides what of its own can travel.
  private def self.module_root?(program : Program, root : String) : Bool
    type = program.types?.try &.[]?(root)
    return false unless type
    type.instance_type.is_a?(NonGenericModuleType) || type.instance_type.is_a?(GenericModuleType)
  end

  # Every method on a declaration, and on the declarations under it.
  #
  # The walk used to stop at the top, which was invisible while the only
  # declarations were a shard's nested types and their methods went unemitted
  # quietly. A class root puts everything one level down, so stopping at the top
  # would have kept nothing at all.
  private def self.keep_type(io : IO, prefix : String,
                             declaration : IyiMod::TypeDecl, counter : Int32) : Int32
    # A private one is in the artifact so the consumer can number it, and naming
    # it here is what the shard's own compiler refuses: `private constant
    # IO::Encoder referenced`.
    return counter if declaration.visibility == "private"

    # A generic has no machine code of its own to keep: its methods exist once
    # per instantiation, the instantiations are the consumer's, and what
    # travels is their source. `uninitialized Holder(T)` is not a thing anybody
    # can write, which is what this file found out.
    return counter unless declaration.type_parameters.empty?

    qualified = "#{prefix}#{declaration.name}"
    receiver = "t#{counter}"
    counter += 1
    io << "  " << receiver << " = uninitialized " << qualified << "\n"
    declaration.methods.each do |signature|
      target = signature.receiver.empty? ? receiver : qualified
      counter = keep_call(io, target, signature, counter)
    end
    declaration.types.each do |nested|
      counter = keep_type io, "#{qualified}::", nested, counter
    end
    counter
  end

  # Both counted through the nesting, because a class root puts every type it
  # carries one level down and a count that stopped at the top read as one.
  private def self.count_types(declarations : Array(IyiMod::TypeDecl)) : Int32
    declarations.sum { |declaration| 1 + count_types(declaration.types) }
  end

  private def self.count_methods(declarations : Array(IyiMod::TypeDecl)) : Int32
    declarations.sum { |declaration| declaration.methods.size + count_methods(declaration.types) }
  end

  # Every type the boundaries in *dir* declare, so this run can name them.
  #
  # A class root's declarations are absolute — `IO`, then `IO::Memory` under it
  # — and a module root's are relative to a name the file does not record. So
  # each is checked against the program rather than trusted: that keeps the
  # first and drops the second, instead of admitting a bare `Any` as though
  # somebody had declared it. What is dropped is counted and printed, because a
  # boundary silently contributing nothing is the failure worth seeing.
  private def self.bound_names(program : Program, dir : String, io : IO) : Set(String)
    names = Set(String).new
    paths = Dir.glob(File.join(dir, "*.iyimod")).sort
    return names if paths.empty?

    io.puts "boundaries already written:"
    paths.each do |path|
      begin
        artifact = IyiMod.read path
      rescue ex
        io.puts "  #{File.basename(path)}: unreadable — #{ex.message}"
        next
      end

      found = Set(String).new
      artifact.exports.types.each { |declaration| collect_known declaration, "", found }
      kept = found.select { |name| declared_type? program, name }
      names.concat kept

      # The consumer reaches an imported module by the camelcase of its path,
      # which is the mapping IV.6 #6 keeps reversible. Only the top-level names
      # are recorded: everything under one is reached through it, so prefixing
      # `IO` carries `IO::Memory` with it.
      prefix = artifact.module_name.split('/').map(&.camelcase).join("::")
      artifact.exports.types.each do |declaration|
        next unless kept.includes? declaration.name
        @@bound_prefix[declaration.name] = "#{prefix}::#{declaration.name}"
        @@bound_module[declaration.name] = artifact.module_name
        program.iyi_bind_boundaries[declaration.name] = artifact.module_name
      end
      io.puts "  %-24s %d types, %d this program can name" % [File.basename(path), found.size, kept.size]
    end
    io.puts
    names
  end

  # Whether the program really has a type by this qualified name.
  private def self.declared_type?(program : Program, qualified : String) : Bool
    table = program.types?
    qualified.split("::").each do |part|
      return false unless table
      found = table[part]?
      return false unless found
      table = found.as?(NamedType).try(&.types?)
    end
    true
  end

  # iyi: the two patterns below were `gsub` with negative lookbehind, and this
  # comment used to say that lookbehind was the one thing this tree's own engine
  # would never do. That is no longer true: `Iyi::Rx` answers both senses of both
  # directions, at any length, so the capability is not the reason any more.
  #
  # They stay written by hand because of cost, not capability. A name boundary is
  # two byte comparisons at a known offset. The same question asked of the engine
  # compiles a program, sweeps a bitmap across the whole text once per assertion,
  # then runs the VM, and every one of those steps is paid on every declaration
  # the tool renames. Reaching for the stdlib `Regex` instead is the other way to
  # lose: it puts `libpcre2-8` back on the compiler's link line, which
  # `bench/dependency_floor.sh` forbids by name.
  #
  # So they read the way `process/shell.cr`, `option_parser.cr` and
  # `semantic_version.cr` read, for the same reason: by hand, over bytes. Both are
  # boundary tests, which is the part a pattern was doing and the part plain code
  # says more plainly.
  #
  # A name boundary here is ASCII: the characters that can continue an
  # identifier are `[A-Za-z0-9_]`, and `:` joins a namespace. Bytes rather than
  # chars because every byte of a multi-byte character is >= 0x80 and so is
  # never one of them.
  private def self.identifier_byte?(byte : UInt8) : Bool
    byte === 0x5F_u8 ||                       # _
      (byte >= 0x30_u8 && byte <= 0x39_u8) || # 0-9
      (byte >= 0x41_u8 && byte <= 0x5A_u8) || # A-Z
      (byte >= 0x61_u8 && byte <= 0x7A_u8)    # a-z
  end

  # True when the byte before *index* could continue a name, so a match there is
  # inside a longer one. `:` counts, which is what keeps `Other::MyLib::Entry`
  # from being read as a `MyLib::` of its own.
  private def self.after_name_byte?(text : String, index : Int32) : Bool
    return false if index == 0
    before = text.to_unsafe[index - 1]
    before === 0x3A_u8 || identifier_byte?(before) # :
  end

  # Every place *needle* appears in *text* on a name boundary, replaced by what
  # *replacement_for* answers. `nil` from the block leaves the occurrence alone.
  private def self.replace_on_boundary(text : String, needle : String,
                                       trailing_name_ends : Bool, & : -> String) : String
    return text if needle.empty? || !text.includes?(needle)

    result = String::Builder.new(text.bytesize)
    index = 0
    while index < text.bytesize
      if text.byte_index(needle, index) == index && !after_name_byte?(text, index)
        after = index + needle.bytesize
        ends_name = !trailing_name_ends ||
                    after >= text.bytesize ||
                    !identifier_byte?(text.to_unsafe[after])
        if ends_name
          result << yield
          index = after
          next
        end
      end
      result.write_byte text.to_unsafe[index]
      index += 1
    end
    result.to_s
  end

  # `MyLib::Entry` becomes `Entry`, and `MyLibOther::X` is left alone — the
  # prefix has to end at a name boundary or this renames types it never owned.
  private def self.strip_root(text : String, root : String) : String
    replace_on_boundary(text, "#{root}::", trailing_name_ends: false) { "" }
  end

  private def self.strip_root(signature : IyiMod::Signature, root : String) : IyiMod::Signature
    IyiMod::Signature.new(
      name: signature.name,
      receiver: signature.receiver,
      parameters: signature.parameters.map { |parameter| strip_root parameter, root },
      block_parameter: strip_root(signature.block_parameter, root),
      return_type: strip_root(signature.return_type, root),
      free_variables: signature.free_variables,
      required: signature.required,
    )
  end

  private def self.strip_root_declaration(declaration : IyiMod::TypeDecl,
                                          root : String) : IyiMod::TypeDecl
    IyiMod::TypeDecl.new(
      name: declaration.name,
      kind: declaration.kind,
      type_parameters: declaration.type_parameters,
      assoc_types: declaration.assoc_types,
      supertraits: declaration.supertraits,
      fields: declaration.fields.map { |(name, type)| {name, strip_root(type, root)} },
      methods: declaration.methods.map { |signature| strip_root signature, root },
      visibility: declaration.visibility,
      types: declaration.types.map { |nested| strip_root_declaration nested, root },
      value: strip_root(declaration.value, root),
      macros: declaration.macros,
      members: declaration.members,
    )
  end

  # Rewrites every bound name in *text* to what the consumer calls it. The name
  # has to stand alone on both sides: `JSON` is bound, `JSONThing` is not.
  private def self.map_names(text : String) : String
    @@bound_prefix.reduce(text) do |carried, (name, qualified)|
      mapped = replace_on_boundary(carried, name, trailing_name_ends: true) { qualified }
      @@bound_used << @@bound_module[name] if mapped != carried
      mapped
    end
  end

  private def self.map_names(signature : IyiMod::Signature) : IyiMod::Signature
    IyiMod::Signature.new(
      name: signature.name,
      receiver: signature.receiver,
      parameters: signature.parameters.map { |parameter| map_names parameter },
      block_parameter: map_names(signature.block_parameter),
      return_type: map_names(signature.return_type),
      free_variables: signature.free_variables,
      required: signature.required,
    )
  end

  private def self.map_names_declaration(declaration : IyiMod::TypeDecl) : IyiMod::TypeDecl
    IyiMod::TypeDecl.new(
      name: declaration.name,
      kind: declaration.kind,
      type_parameters: declaration.type_parameters,
      assoc_types: declaration.assoc_types,
      supertraits: declaration.supertraits,
      fields: declaration.fields.map { |(name, type)| {name, map_names(type)} },
      methods: declaration.methods.map { |signature| map_names signature },
      visibility: declaration.visibility,
      types: declaration.types.map { |nested| map_names_declaration nested },
      value: map_names(declaration.value),
      macros: declaration.macros,
      members: declaration.members,
    )
  end

  # What an iyi program calls this shard, which is not a matter of taste.
  #
  # The symbol is the whole reason. Both sides mangle alike, so `Greeter.polite`
  # is `*Greeter@Greeter::polite<String>:String` compiled from either language —
  # but only if the consumer's module *is* `Greeter`, and the consumer builds
  # that name by camelcasing the module path it imported. `downcase` broke the
  # round trip for every name with an inner capital: `MyGreeter` became
  # `mygreeter` became `Mygreeter`, which mangles to a symbol the shard's object
  # file does not contain, and nothing says so until the linker does.
  #
  # `::` is `/` because that is how iyi spells a nested module (IV.6 #6), and
  # each segment is `camelcase` run backwards.
  #
  # `String#underscore` is *not* that inverse and using it was the bug this
  # replaced: it answers `json` for `JSON`, which camelcases back to `Json`.
  # `camelcase` upper-cases the first letter of every underscore group, so its
  # inverse starts a group at every upper-case letter — `j_s_o_n`, which is a
  # legal iyi path and comes back `JSON`. `HTTPServer` is `h_t_t_p_server` and
  # comes back whole; `underscore` gave `http_server` and lost it.
  # Public, because the build that fills this artifact's object code has to
  # find the file `tool bind` wrote and only this rule says where it is.
  def self.iyi_module_name(root : String) : String
    root.split("::").map do |segment|
      # By hand, for the same reason as the boundary tests above: a pattern here
      # costs the whole compiler a C library (Appendix B #22).
      broken = String::Builder.new(segment.bytesize * 2)
      segment.each_char do |character|
        if character.ascii_uppercase?
          broken << '_'
          broken << character.downcase
        else
          broken << character
        end
      end
      broken.to_s.lchop('_')
    end.join("/")
  end

  # Whether that name comes back as the name it was made from.
  #
  # Almost everything does, now that the inverse above is the real one:
  # `JSON`, `URI`, `HTTPServer`, `Base64`. What does not is a name the grammar
  # cannot spell — one already carrying an underscore, say, which would need two
  # in the path and `camelcase` reads two as one. The check stays because the
  # failure it catches is the worst-behaved kind: the mangled symbol carries
  # whichever name the side that compiled it had, so a producer writing
  # `*Foo_Bar@Foo_Bar::...` and a consumer asking for `*FooBar@FooBar::...` agree
  # on everything a compiler checks and disagree only where `ld` looks.
  private def self.round_trips?(root : String) : Bool
    consumer_name(root) == root
  end

  # What the consumer will call it, having imported the module.
  private def self.consumer_name(root : String) : String
    iyi_module_name(root).split('/').map(&.camelcase).join("::")
  end

  # `Log` written `::Log`, where leaving it bare would find something else.
  #
  # An artifact's declarations are rendered *inside* the module they belong to,
  # so a bare name is looked up there first. `Kemal::Log` is a constant and
  # `::Log` is Crystal's class, and an accessor declared to return `Log` inside
  # `module Kemal` finds the constant: *`Kemal::Log` is not a type, it's a
  # constant*. Only a top-level name can be shadowed this way, and only a name
  # of Crystal's — the shard's own are reached through the root on purpose.
  private def self.global_name(name : String, root : String) : String
    return name if name.includes?("::") || name.starts_with?("::")
    return name unless @@crystal_types.includes?(name)
    "::#{name}"
  end

  # Every type defined under Crystal's own source, by qualified name.
  #
  # Read from where each type was written rather than from a list: a list is a
  # claim that everything not in it does not matter, and this file has already
  # recorded what that costs once.
  private def self.crystal_library_types(program : Program) : Set(String)
    names = Set(String).new
    library = program.requires.find(&.ends_with?("prelude.cr"))
    return names unless library
    root = File.dirname(library)

    collect_crystal_types program.types?, "", root, names
    names
  end

  private def self.collect_crystal_types(types : Hash(String, Type)?, prefix : String,
                                         root : String, names : Set(String)) : Nil
    return unless types

    types.each do |name, type|
      next unless type.is_a?(NamedType)
      written_here = type.locations.try(&.any? { |location| location.filename.to_s.starts_with?(root) })
      names << "#{prefix}#{name}" if written_here
      collect_crystal_types type.types?, "#{prefix}#{name}::", root, names
    end
  end

  # The shard's requires of *Crystal's library*, for the consumer to replay.
  #
  # A unit numbers the types its source brought in — `Radix` reaches
  # `Hash(String, HTTP::Cookie)` — and a consumer whose prelude is Crystal's
  # still does not have every file of it. So `require "http/cookie"` travels.
  #
  # Crystal's only. A require that resolved into somebody else's `lib` is
  # another shard, and another shard is another boundary: replaying it here
  # would have the consumer compile from source the very thing an artifact
  # exists to spare it. Those arrive as import edges instead.
  #
  # Told apart by where each one resolved, which is why the resolution is what
  # was recorded rather than the name alone.
  private def self.crystal_requires(program : Program) : Array(String)
    library = program.requires.find(&.ends_with?("prelude.cr"))
    return [] of String unless library
    root = File.dirname(library)

    names = program.iyi_crystal_requires.compact_map do |name, resolved|
      name if resolved.starts_with?(root)
    end
    names.sort!.uniq!
    names
  end

  # The bodies a generic's methods travel as, keyed the way the reader looks
  # them up. Reset per run with everything else this file accumulates.
  @@mono_bodies = {} of String => String

  # A generic type: its parameters, its fields, and its methods with bodies.
  #
  # `new` is left out on purpose and the reason is already in IV.2: it is
  # synthesized from `initialize` rather than read from an artifact, so a
  # consumer makes its own — and one carried here would meet it at the linker
  # as a duplicate.
  private def self.generic_declaration(name : String, type : GenericClassType,
                                       by_owner, root : String) : IyiMod::TypeDecl?
    parameters = type.type_vars
    signatures = [] of IyiMod::Signature

    { {type.to_s, false}, {type.metaclass.to_s, true} }.each do |(owner, on_metaclass)|
      by_owner[owner]?.try &.each do |method|
        next if method.name == "new"
        next unless method.verdict.ready? || method.inferred
        next unless method.callable?
        # A type variable is nameable inside the type that binds it, which is
        # the whole point of carrying the parameters beside the methods.
        next unless method.signature_types.all? do |written|
                      nameable?(written, root) || parameters.any? { |bound| written == bound }
                    end
        next unless body = method.body

        signature = IyiMod::Signature.new(
          name: method.name,
          receiver: on_metaclass && method.receiver.empty? ? "self" : method.receiver,
          parameters: method.params.map { |(argument, restriction)| "#{argument} : #{restriction}" },
          block_parameter: method.written_block,
          return_type: method.answer.not_nil!,
          free_variables: [] of String,
          required: false,
        )
        signatures << signature
        @@mono_bodies[IyiMod.mono_body_key(name, signature)] = body
      end
    end

    # No guard on an empty method list, and that is the point. A consumer may
    # need only to *name* this type — `Kemal` refers to
    # `Array(Radix::Node(...))` and never calls a `Node` method — and naming is
    # what a declaration is for. Dropping the empty ones is what left `Kemal`
    # waiting on a type whose methods it had no use for.
    fields = [] of {String, String}
    type.instance_vars.each do |field, variable|
      fields << {field, variable.type?.try(&.devirtualize.to_s) || "?"}
    end

    nested = [] of IyiMod::TypeDecl
    collect_declarations type, by_owner, root, nested

    IyiMod::TypeDecl.new(
      name: name,
      kind: type.type_desc.lchop("generic "),
      type_parameters: parameters,
      assoc_types: [] of String,
      supertraits: [] of String,
      fields: fields,
      methods: signatures.sort_by(&.name),
      visibility: type.private? ? "private" : "pub",
      # A generic holds types too, and leaving them behind is how
      # `Kemal::LRUCache::Node(K, V)` went missing while `LRUCache` travelled.
      types: nested,
    )
  end

  # An enum, as its members and the integer they are numbered on.
  #
  # A member is a `Const` under the enum whose value is the number the compiler
  # gave it, so this reads what is there rather than renumbering: a consumer
  # that guessed the numbering would agree with the shard's object file only by
  # luck, and the object file is what it links against.
  private def self.enum_declaration(name : String, type : EnumType,
                                    private_type : Bool) : IyiMod::TypeDecl
    members = [] of {String, String}
    type.types?.try &.each do |member, constant|
      next unless constant.is_a?(Const)
      members << {member, constant.value.to_s}
    end

    IyiMod::TypeDecl.new(
      name: name,
      kind: "enum",
      type_parameters: [] of String,
      assoc_types: [] of String,
      supertraits: [] of String,
      fields: [] of {String, String},
      methods: [] of IyiMod::Signature,
      visibility: private_type ? "private" : "pub",
      types: [] of IyiMod::TypeDecl,
      # Written even when it is the default, because a member's number is only
      # the same number if the width is.
      value: type.base_type.to_s,
      macros: [] of String,
      members: members,
    )
  end

  # `TABLE = ["zero", "one", "two"]`, for every constant of *root*'s own that a
  # consumer could rebuild — including the ones inside its types.
  #
  # Its own only. A unit refers to Crystal's constants too — `Int::DIGITS_BASE62`
  # is reached because `Array#[]` can raise and raising formats an integer — and
  # those belong to the library the consumer already has under `--crystal`.
  # Writing them here would define somebody else's constant twice.
  #
  # A nested one is written `Inner::X = ...`, which defines rather than reopens.
  # That was left out once on the assumption it did not, which was a guess and
  # wrong: Crystal takes a qualified assignment wherever the namespace exists,
  # and the declarations above this text are what make it exist.
  private def self.constant_source(program : Program, root : String) : String
    root_type = program.types?.try &.[]?(root)
    return "" unless root_type.is_a?(NamedType)

    lines = [] of String
    collect_constant_source root_type, "", root, lines
    lines.sort!
    lines.empty? ? "" : lines.join('\n')
  end

  private def self.collect_constant_source(owner : NamedType, prefix : String,
                                           root : String, lines : Array(String)) : Nil
    owner.types?.try &.each do |name, type|
      case type
      when Const
        # Not the compiler's own. A regex literal is cached in a constant named
        # `$Regex:0`, which is not a name anybody wrote and not one anybody can
        # write — the consumer makes its own when it compiles the body that
        # needed it.
        next if name.starts_with?('$')
        # A value the consumer cannot name is one it cannot rebuild, and a
        # constant it cannot rebuild is better left undefined than defined wrong.
        answer = type.value.type?.try(&.devirtualize.to_s)
        next if answer && !nameable?(answer, root)
        lines << "#{prefix}#{name} = #{type.value}"
      when NamedType
        next if type.is_a?(GenericType)
        next if type.private?
        # An enum's members are its own and travel with it. Written out here
        # they would be assignments into a type that already has them.
        next if type.is_a?(EnumType)
        collect_constant_source type, "#{prefix}#{name}::", root, lines
      end
    end
  end

  # The foreign types one signature waits on.
  private def self.foreign_names(method : BindMethod, root : String) : Set(String)
    names = Set(String).new
    method.signature_types.each do |type|
      Rx.scan(type, BIND_TYPE_NAME).each do |match|
        part = match[0].not_nil!
        next if part == "class"
        names << part unless nameable_name?(part, root)
      end
    end
    names
  end

  # The order to declare them in: the one that unblocks the most first.
  #
  # Greedy rather than optimal, and the difference does not matter — what this
  # answers is "where does the work start", and the head of the list is the
  # same either way.
  private def self.blocked_by(program : Program, known : Array(BindMethod),
                              root : String) : Array(String)
    counts = Hash(String, Int32).new(0)
    known.each do |method|
      # Only what somebody could actually declare. A method waiting on a free
      # variable stays waiting, and the count above still holds it there — but
      # it does not belong on a list of work.
      foreign_names(method, root).each do |name|
        counts[name] += 1 if declared_type? program, name
      end
    end
    counts.to_a.sort_by { |(name, count)| {-count, name} }.map { |(name, _)| name }
  end

  # A type an iyi program can name: the shard's own, or one of the prelude's.
  #
  # Every name inside it, not just the one in front. `Hash(Exception.class,
  # Proc(HTTP::Server::Context, Exception, String))` begins with a type the
  # prelude has and is made almost entirely of types it does not, and reading
  # only the head counted it as writable — the measurement flattering itself.
  private def self.nameable?(name : String, root : String) : Bool
    Rx.scan(name, BIND_TYPE_NAME).all? do |match|
      part = match[0].not_nil!
      next true if part == "class" # `Exception.class` is read as its own name
      nameable_name?(part, root)
    end
  end

  private def self.nameable_name?(name : String, root : String) : Bool
    return true if name == root || name.starts_with?("#{root}::")
    bare = name.lchop("::")
    @@builtin.includes?(bare) || @@bound.includes?(bare) || @@crystal_types.includes?(bare)
  end

  # Only the types the shard declares. A type it merely reopened belongs to
  # somebody else, and R-3 is what refuses to carry it here.
  private def self.collect_bind(types : Hash(String, Type)?, root : String,
                                methods : Array(BindMethod)) : Nil
    return unless types

    types.each_value do |type|
      next unless type.is_a?(NamedType)
      name = type.to_s
      next unless name == root || name.starts_with?("#{root}::")

      each_bind_def(type) { |a_def| methods << classify_bind(type, a_def) }
      each_bind_def(type.metaclass) { |a_def| methods << classify_bind(type.metaclass, a_def) }

      collect_bind type.types?, root, methods
    end
  end

  private def self.each_bind_def(type : Type, & : Def ->) : Nil
    defs = type.as?(ModuleType).try &.defs
    return unless defs

    defs.each_value do |list|
      list.each do |item|
        a_def = item.def
        next unless a_def.visibility.public?
        # A method with no location is the compiler's own — `allocate` exists
        # on every type and nobody wrote it. A boundary carries what a shard's
        # author wrote, and `new` comes back through `initialize`.
        next unless a_def.location
        yield a_def
      end
    end
  end

  private def self.classify_bind(owner : Type, a_def : Def) : BindMethod
    verdict =
      if a_def.args.any? { |arg| arg.restriction.nil? }
        BindVerdict::NeedsHuman
      elsif a_def.return_type
        BindVerdict::Ready
      else
        BindVerdict::NeedsReturn
      end

    inferred = nil
    refused = nil
    checked = BindCheck::NotWritten
    produced = nil
    written = resolve_restriction(owner, a_def.return_type)

    if verdict.needs_return?
      inferred, refused = infer_return(owner, a_def)
    elsif written
      # The other half of rule 1. A method that writes its return type was
      # copied out verbatim and never instantiated, so nothing ever held the
      # two against each other — and a written restriction is not the answer a
      # caller gets. Crystal narrows it to what the body produced: `def f :
      # String?` whose body returns a `String` types its call `String`, not
      # `String?`. A consumer told the union holds one where the object code
      # answers a bare pointer, which is rule 1's "returns something of another
      # type" exactly. So ask this half the question the other half answers.
      produced, refused = infer_return(owner, a_def)
      checked =
        if produced.nil?
          BindCheck::Unchecked
        elsif produced == written
          BindCheck::Agrees
        else
          BindCheck::Disagrees
        end
      produced = nil unless checked.disagrees?
    end

    BindMethod.new(
      owner: owner.to_s,
      name: a_def.name,
      verdict: verdict,
      block: !a_def.block_arg.nil? || !a_def.block_arity.nil?,
      untyped: a_def.args.select(&.restriction.nil?).map(&.name),
      location: a_def.location.try(&.to_s) || "?",
      inferred: inferred,
      refused: refused,
      body: a_def.body.to_s,
      # The return type is asked the same question the parameters are. `Int` is
      # the head of a family on either side of the arrow, and a method that
      # answers one has a symbol per member exactly as a method that takes one
      # does. Asking it of the arguments alone was half the question.
      storable: a_def.args.all? { |arg| storable_restriction?(owner, arg.restriction) } &&
                (a_def.return_type.nil? || storable_restriction?(owner, a_def.return_type)),
      params: a_def.args.map { |arg| {arg.name, resolve_restriction(owner, arg.restriction) || "?"} },
      returns: written,
      checked: checked,
      produced: produced,
      receiver: a_def.receiver.try(&.to_s) || "",
      # `&block : Context -> B` travels as written. A block whose type nobody
      # wrote cannot: R-2 asks the block for its types like everything else.
      written_block: a_def.block_arg.try { |argument| argument.restriction ? "&#{argument}" : "" } || "",
    )
  end

  # The type a restriction names, rather than the text somebody typed.
  #
  # A method inside `JSON::Token` writes `kind : Kind`, and reading that as
  # written makes `Kind` a type nobody has declared — when it is
  # `JSON::Token::Kind`, the shard's own, already travelling. Every such
  # spelling inflated the count of what a boundary waits on, and inflated it in
  # one direction: *towards the core*, which is the claim the count was being
  # used to support. `self` is the same mistake with a shorter name — a method
  # returning `self` in `URI` returns `URI` and waits for nobody.
  #
  # A consumer is the other reason. It writes against this boundary from
  # outside, where `Kind` names nothing; a declaration that travels has to say
  # what it means from there.
  #
  # Resolution can fail — a free variable, `_`, a restriction this scope cannot
  # see — and then the written text stands, which is what this did for
  # everything before.
  private def self.resolve_restriction(owner : Type, node : ASTNode?) : String?
    return nil unless node
    written = node.to_s
    return written if written == "_"
    return owner.instance_type.devirtualize.to_s if node.is_a?(Self)

    type = owner.lookup_type?(node)
    return written unless type
    # A free variable is a name this method binds, not one anybody declares.
    return written if type.is_a?(TypeParameter)
    type.devirtualize.to_s
  rescue
    node.to_s
  end

  # Whether a variable could have the type this restriction names.
  private def self.storable_restriction?(owner : Type, node : ASTNode?) : Bool
    return false unless node
    type = owner.lookup_type?(node)
    return false unless type
    instance = type.instance_type
    return false if instance.is_a?(GenericClassType)
    instance.can_be_stored?
  rescue
    false
  end

  # What a caller of this method is handed.
  #
  # Not what the shard wrote, which is a different question and the one the
  # written half used to answer with its own premise: Crystal narrows a return
  # restriction to what the body produced, so this can disagree with a `def`
  # that spells its return out. Both halves ask it now.
  private def self.infer_return(owner : Type, a_def : Def) : {String?, String?}
    call, refused = instantiate(owner, a_def)
    return {nil, refused} unless call

    type = call.type?
    return {nil, "no type"} unless type

    # `Foo+` is how a virtual type prints, and it is a fact about this build's
    # dispatch rather than a name anybody can write down. A declaration says
    # `Foo`, which is what the call site means and what parses.
    {type.devirtualize.to_s, nil}
  end

  # Instantiate a method nobody called, and hand back the call.
  #
  # This is the whole trick, and it is why a shard's untyped surface is not the
  # wall it looks like. Crystal types a method when something calls it, so a
  # library's own methods have no types until a program uses them — but a
  # method whose parameters are written down can be *called on purpose*, with
  # one synthesised argument per parameter, and the answer is the same answer a
  # real call would have produced.
  #
  # What it cannot do is written down beside what it can. A block is the honest
  # one: its type depends on what the caller passes, so there is no single
  # answer to read.
  private def self.instantiate(owner : Type, a_def : Def) : {Call?, String?}
    # A block whose own type is written is not the problem; one whose output is
    # `_`, or which was never annotated, is. What such a method returns depends
    # on what the caller passes, and there is no single answer to read.
    if block_arg = a_def.block_arg
      restriction = block_arg.restriction
      return {nil, "block is not annotated"} unless restriction
      return {nil, "block returns `_`"} if restriction.to_s.includes?("_")
    end
    return {nil, "yields without a block parameter"} if a_def.block_arity && !a_def.block_arg
    return {nil, "splat"} if a_def.splat_index || a_def.double_splat
    return {nil, "generic type"} if owner.instance_type.is_a?(GenericType)
    return {nil, "abstract"} if a_def.abstract?

    args = [] of ASTNode
    a_def.args.each do |arg|
      restriction = arg.restriction
      return {nil, "no restriction"} unless restriction

      type = owner.lookup_type?(restriction)
      return {nil, "cannot resolve #{restriction}"} unless type
      return {nil, "generic parameter"} if type.is_a?(TypeParameter)

      args << Var.new(arg.name).tap(&.set_type(type.virtual_type))
    end

    receiver = Var.new("self").tap(&.set_type(owner))
    call = Call.new(receiver, a_def.name, args)
    call.scope = owner
    call.recalculate
    {call, nil}
  rescue ex : Iyi::CodeError
    {nil, ex.message.to_s.lines.first?.to_s}
  rescue ex
    {nil, ex.message.to_s.lines.first?.to_s}
  end
end
