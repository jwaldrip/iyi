require "crystal/digest/md5"
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
# Every section named in `Section` is written now. An unknown one is skipped and
# a known one that is absent is simply absent, which is what the table is for.
module Iyi::IyiMod
  MAGIC = "IYIMOD\0\0".to_slice

  # Bumped when the layout of any section changes incompatibly. IV.5: a
  # `.iyimod` from another version is rejected and rebuilt, never migrated.
  FORMAT_VERSION = 24_u32

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

    # iyi: the types this module's object code refers to a type id of, by name.
    # Not in IV.1's table either — see IV.1g.
    TypeIds = 9

    # iyi: the constants this module's object code reads, by name. Same reason
    # as `TypeIds` and a different question, so a section of its own — see
    # IV.1g.
    Constants = 10

    # iyi: under `--crystal`, the library files this module required, in the
    # order it required them. Same reason as `TypeIds` again — see IV.1g.
    Requires = 11

    # iyi: what the synthesised regex constants in `Constants` were made from.
    # A name is enough for every other constant there and not for these — see
    # `Artifact#regexes` and IV.1g.
    Regexes = 12

    # iyi: the class variables this module's object code refers to, as
    # `Owner::@@name`. `Constants` asked of a global — see IV.2.
    ClassVars = 13

    # iyi: the pointer maps of the types this module owns, one `TypeLayout`
    # per type, keyed in the file by the type's name. Same reason as
    # `TypeIds` for keying by name rather than by the number: two programs
    # number their types differently, and the numbering is the consuming
    # program's (IV.1g). What an entry carries is GC_DESIGN.md Stage 1.
    #
    # 14 rather than 12: this landed as 12 here while `Regexes` took 12
    # upstream, and a section number is on-disk format, so the one that had
    # not shipped in a release moved.
    Layouts = 14
  end

  # A regex literal's constant: the name its object code reads, and what a
  # consumer has to build under that name.
  #
  # *options* is the flags as the number they are stored as rather than as the
  # enum, because the enum belongs to the compiler that wrote this and the file
  # outlives it. `Regex::Options.new` on the far side turns it back.
  record RegexConst, name : String, pattern : String, options : UInt32

  # A class variable a module's object code refers to: `Owner::@@name`, and how.
  #
  # *lazy* is true when the unit calls `~Owner::name:read` — the main-module
  # function that initialises on first use — and false when it reads the global
  # directly. The consumer owes exactly the one that was emitted, and it cannot
  # be inferred on the far side: a program under iyi's prelude never takes the
  # lazy branch, because that prelude has no `__crystal_once`, while one under
  # Crystal's takes it for anything with a live initialiser.
  record ClassVarRef, name : String, lazy : Bool

  class Error < Iyi::Error
  end

  # IV.3's three hashes — what decides whether a build is actually incremental.
  #
  # The property the split exists for: **changing a body must not change the
  # interface hash.** One hash over the whole file would make every dependent
  # rebuild for every edit, and the artifact would buy nothing but a slower
  # first build.
  #
  # *interface* covers what a consumer typechecks against — the exports, the
  # `using` directives that resolve their annotations, and which modules this
  # one imports. A body is not in it, so editing one leaves every dependent's
  # own artifact valid.
  #
  # *implementation* covers what a consumer *compiles*: the bodies that travel
  # because it has to specialise them, and the module's initialiser, which is
  # spliced into the consuming program and runs there. IV.3 says a change here
  # need not make a dependent re-typecheck, only re-codegen; at module
  # granularity there is no way to say that, so a dependent that has one of
  # these edges is invalidated whole and told nothing finer.
  #
  # *source* is IV.3's Private — private types, ordinary bodies, everything
  # that is neither of the above. At module granularity that is the module's
  # own source text, which is also the thing that answers the first question a
  # cache has: does this artifact still describe the file it was written from.
  #
  # **Computed from the front end alone**, before codegen. An artifact written
  # by a `--no-codegen` build and one written by a full build describe the same
  # module and must hash the same, or a build that typechecks would invalidate
  # the artifact a build that generates code had just written.
  record Hashes,
    interface : String = "",
    implementation : String = "",
    source : String = "" do
    def self.empty : Hashes
      new
    end

    def empty? : Bool
      interface.empty? && implementation.empty? && source.empty?
    end
  end

  # One edge of the import DAG, with what the module on the far end hashed to
  # when this one was compiled against it (IV.3).
  #
  # The hashes are what makes an artifact a cache rather than a claim: a build
  # that finds `app/box.iyimod` can ask whether the `std/list` it describes is
  # the `std/list` this build has, and read the artifact only if it is.
  #
  # Both hashes, because a consumer depends on both halves of what a module
  # gives it. The interface is what its own declarations were typechecked
  # against; the implementation is the bodies it specialised and the
  # initialiser it spliced in, which it compiled into its own object code.
  record ImportEdge,
    module_name : String,
    interface : String = "",
    implementation : String = ""

  # A cache key rather than a signature, which is why MD5 is enough and why the
  # compiler's own vendored copy is the one to use: `.iyimod` decides what to
  # rebuild, and nothing downstream trusts an artifact it did not write.
  def self.digest(value : String) : String
    ::Crystal::Digest::MD5.hexdigest(value)
  end

  # iyi: what the section table records so a damaged section is refused rather
  # than compiled against (IV.1, format v19).
  #
  # A single flipped byte in an artifact used to build: seven times out of ten
  # it landed somewhere that changed nothing, and the other three reached the
  # linker, which failed with a message that never mentioned the artifact. A
  # compiled artifact travels — copied into a CI cache, downloaded, restored
  # from a backup — and the reader is the last place that can still tell.
  #
  # Per section rather than per file, because a front-end read seeks past the
  # object code and hashing the whole file would put the largest section back
  # on the path this format exists to keep short. A section that is not read is
  # not checked, and nothing is compiled against it either.
  def self.checksum(payload : Bytes) : UInt64
    bytes = ::Crystal::Digest::MD5.digest(payload)
    value = 0_u64
    8.times { |index| value = (value << 8) | bytes[index] }
    value
  end

  # IV.3's hashes for *artifact*, whose module was read from *source*.
  #
  # Taken from what the artifact carries rather than from the file it came
  # from, which is what makes the interface hash mean anything: it is over the
  # exports themselves, so an edit that does not reach them does not move it,
  # and every dependent stays valid.
  def self.hashes_for(artifact : Artifact, source : String) : Hashes
    interface = IO::Memory.new
    interface.write encode_exports(artifact)
    write_strings interface, artifact.usings
    # The edges by name, because which modules resolve a signature's names is
    # part of what that signature means — not their hashes, which are what a
    # *dependent* records about this module and would make this one move for a
    # change it does not see.
    write_strings interface, artifact.import_names
    # Beside the imports and for the reason they are there: a require is what
    # brings the types an exported signature names into existence, so changing
    # one changes what those signatures mean.
    write_strings interface, artifact.requires

    implementation = IO::Memory.new
    implementation.write encode_mono_bodies(artifact)
    # With the bodies rather than with the exports: a macro is not reachable
    # from another module, and editing one changes what a consumer compiles.
    implementation.write encode_macro_bodies(artifact)
    write_string implementation, artifact.initialiser
    implementation.write_byte(artifact.has_initialiser ? 1_u8 : 0_u8)

    Hashes.new(
      interface: digest(interface.to_s),
      implementation: digest(implementation.to_s),
      source: digest(source),
    )
  end

  # The value the `compiler_version` field is compared against.
  #
  # An equality test rather than a range, because IV.5 rejects and rebuilds an
  # artifact rather than migrating it. What the two sides have to agree on is
  # the **released version**: two builds of iyi 0.1.0 read each other's
  # artifacts, which is what makes a `.iyimod` something to hand to somebody
  # rather than a file that only its own build can open. The target and the
  # flags are checked beside this one and are no less part of the answer.
  #
  # A development version keeps the build commit, and that is not caution. A
  # released number names one compiler; `0.2.0-dev` names every compiler
  # between two releases, and two of those can disagree about anything at all.
  # So the rule is stated by what the version *is*: named releases interoperate,
  # the versions between them do not.
  def self.compiler_version : String
    version = Config.iyi_version
    if version.ends_with?("-dev") && (commit = Config.build_commit)
      "#{version}+#{commit}"
    else
      version
    end
  end

  # One exported function's signature — a `pub def` (R-2).
  #
  # Types are carried as the **source text of the annotation the author wrote**,
  # not as a rendering of the inferred `Iyi::Type`. R-2 is what makes that
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

  # A type the module declares: `pub struct`, `pub class`, `pub trait` — and,
  # since the object code started travelling, the ones it does not export.
  #
  # Not `pub enum`, which the parser refuses: `pub` takes a def, a class, a
  # struct and a trait and nothing else. There is no `enum` in the prelude or
  # in any sample, so nothing has asked (SPEC.md IV.2).
  #
  # *visibility* is what was written, and it is what keeps R-2b true on the far
  # side: a type carried without `pub` is declared by the consumer and reachable
  # from nowhere, which is exactly what it is when the module is read from
  # source. An unexported type travels at all because the module's own machine
  # code refers to it — `Array(Secret):type_id` is resolved from a definition in
  # the consuming program, and a program can only number a type it has.
  #
  # A type nobody may call travels as its name, its kind and its fields, and
  # its methods stay behind: the consumer has no way to reach them, and the
  # module's own object code already defines them. That is also why carrying
  # them would be worse than useless — R-2's block rule would start refusing
  # modules over a private method's unannotated block.
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
  # *types* is what this type declares in turn. A nested type belongs to its
  # container rather than to the module's surface (R-2 governs the unit's own
  # body), so it is rendered where it was written and carries the visibility it
  # was written with.
  #
  # *value* is what an `alias` is equal to, and it is empty for everything
  # else. An alias has neither a layout nor an id, and it travels anyway,
  # because a declaration that does names it: a carried record's `handler :
  # Handler` is the text the module was written with, and a consumer without
  # the alias reads it as an undefined constant.
  record TypeDecl,
    name : String,
    kind : String,
    type_parameters : Array(String),
    assoc_types : Array(String),
    supertraits : Array(String),
    fields : Array({String, String}),
    methods : Array(Signature),
    visibility : String = "pub",
    types : Array(TypeDecl) = [] of TypeDecl,
    value : String = "",
    macros : Array(String) = [] of String,
    # iyi: an enum's members, `{"Small", "0"}`. Its own field rather than a
    # reading of `fields`, because a member is not a field: it has a value where
    # a field has a type, and the two render differently and mean differently.
    members : Array({String, String}) = [] of {String, String},
    # iyi: the type's own class variables, `{"@@seen", "Int32", "0"}` — name,
    # resolved type, and the initialiser as written, empty when it has none.
    #
    # Beside `fields` because it is the same kind of thing one level up: not
    # part of the surface a consumer writes against, and something the consumer
    # has to *allocate*. A class variable is a global, the methods that read it
    # travel as machine code referring to it by name, and the global itself
    # lives in a main module that never travels — so without this a module with
    # one failed R-1's own round trip on an undefined symbol.
    #
    # Its own field rather than a reading of `fields`, and for the reason
    # `members` is: it renders differently and means differently. A field is
    # allocated per instance and has no value here; a class variable is
    # allocated once and its value is half of what has to arrive.
    class_vars : Array({String, String, String}) = [] of {String, String, String}

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
  # *carried_functions* is the other half of the sentence above, and it arrived
  # for the same reason a type the module keeps to itself did: a body that
  # travels calls them. `run` takes a block, so the consumer compiles it, and
  # `run` calls a `helper` the module never exported. They are rendered without
  # `pub`, so the consumer declares them and may not name them — which is what
  # they are when the module is read from source.
  record Exports,
    functions : Array(Signature),
    types : Array(TypeDecl),
    impls : Array(ImplRecord),
    carried_functions : Array(Signature) = [] of Signature do
    def self.empty
      new([] of Signature, [] of TypeDecl, [] of ImplRecord)
    end

    def empty?
      functions.empty? && types.empty? && impls.empty? && carried_functions.empty?
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
  # GC_DESIGN.md Stage 1: the pointer map of one type, so a collector reads
  # an object's shape out of the artifact instead of discovering it at run
  # time. Heap-layout precision is the one REQUIREMENT SPEC.md II.5 makes of
  # the collector design, and this record is where it is kept.
  #
  # *type_id* is the design's key, and it carries the producing build's
  # numbering. The section keys its entries by the type's NAME for the reason
  # `TypeIds` is names rather than values: the numbering belongs to the
  # consuming program, so a consumer re-keys by name to its own ids.
  #
  # *alloc_size* is what an allocation of the type occupies: the LLVM
  # struct's size, tail padding included. *scan_cap* is the unrounded
  # instance size, the end of the last field. It caps the conservative
  # fallback a collector takes when it finds no layout for an object, so the
  # fallback word-scans real fields and stops before tail padding.
  #
  # *scan_offsets* is every byte offset in the object that holds a pointer
  # word: reference fields, `Pointer(T)` fields, a proc's context word, and
  # the pointer words inside inlined struct, tuple and static array fields,
  # flattened to the object they sit in. A mixed union field contributes the
  # pointer words of every arm, because which arm is live is runtime
  # business; over-marking retains, and under-marking loses.
  #
  # The offsets describe the object as it is laid out today, type id word
  # included. When Stage 2 puts the mark word header on live objects the
  # map shifts with it, and that migration is Stage 2's.
  #
  # *noscan_offsets* is empty today, on purpose, and a guess would be worse.
  # The design's two examples do not classify yet: a weak reference is
  # registration-based (Boehm's disappearing links), with nothing in the type
  # system marking the field, and an `Array(Int32)` buffer's pointee holds no
  # pointers, which a headered collector already gets for free because raw
  # buffer memory carries no type id to recurse into. What noscan *means* is
  # Stage 6's to say; until then the empty list says nothing falsely.
  record TypeLayout,
    type_id : Int32,
    alloc_size : UInt32,
    scan_cap : UInt32,
    scan_offsets : Array(UInt16),
    noscan_offsets : Array(UInt16)

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

    # The modules this one imports, in the order the DAG edges were recorded,
    # each with what it hashed to when this module was compiled against it.
    # III.5's initialisation order is derivable from these.
    # Settable, because an edge's hashes are filled in once every module in the
    # build has been described: what a dependency compiled here hashes to is
    # not known while this artifact is being built (IV.3).
    property imports : Array(ImportEdge)

    # The same, as module paths — which is all a reader that only wants to load
    # them needs.
    def import_names : Array(String)
      imports.map &.module_name
    end

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

    # The macros this module declares, as source text.
    #
    # A macro has no machine code to arrive as, and a body that travels may
    # call one: the consumer compiles `run`, `run` writes `twice(n)`, and
    # `twice` is a macro of the module that `run` came from. Without them the
    # artifact is refused on a name its own module has.
    #
    # All of them, rather than the ones somebody marked: `pub` does not take a
    # macro, so none of these is reachable from outside — they are here for the
    # bodies that travel to expand against, exactly as the unexported defs
    # beside them are here to typecheck against.
    #
    # Source text, like the bodies and the initialiser and for the same reason:
    # IV.1's table says serialised AST, which is the faster answer and the one
    # with a second grammar to keep correct.
    getter macro_bodies : Array(String)

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

    # The types this module's object code refers to a type id of, by name.
    #
    # A type id is an external reference — the number belongs to the program,
    # not to the module — so the unit that travels here leaves
    # `Array(Item):type_id` undefined and the consumer's `_main` defines it.
    # It can only define an id for a type it has, and `Array(Item)` exists in
    # the producing build because of a body that stays behind: nothing the
    # consumer reads would ever make it. So the name travels and the consumer
    # instantiates it, which is enough — the type has to be *numbered*, not
    # used.
    #
    # Names rather than numbers, for the reason the section exists: two
    # programs number their types differently, and an artifact that carried a
    # value would be carrying this build's numbering into somebody else's.
    #
    # Settable alongside `object_code`, and for the same reason: which ids a
    # unit refers to is not known until it has been generated.
    property type_ids : Array(String)

    # The constants this module's object code reads, by name.
    #
    # A constant is initialised only where something read it, and on the far
    # side of an artifact the only reader is machine code the consumer did not
    # compile — so nothing marked `Kemal::Dsl::APP` used and nothing defined it,
    # while every exported method in the unit called through it. The names
    # travel and the consumer marks them used, which puts them back on the
    # ordinary path: their initialiser is already in the module's own top level
    # and already runs in III.5's order.
    #
    # Settable alongside `object_code`, and for the same reason.
    property constants : Array(String)
    # The pointer maps of the types this module owns, as `(name, layout)`
    # pairs sorted by name. See `TypeLayout`.
    #
    # Settable alongside `object_code`, and for the same reason: a byte
    # offset is LLVM's answer about a lowered type, which does not exist
    # until codegen has run. From a `--no-codegen` build this is empty,
    # exactly as the object code is absent from one.
    property layouts : Array({String, TypeLayout})

    # What the synthesised regex constants above were made from.
    #
    # `constants` carries a name, and for every other constant in it a name is
    # the whole of what a consumer needs: it already has Crystal's, and the ones
    # this module declared arrive in the initialiser that travels as source. A
    # regex literal's constant is neither. Nobody wrote it — the compiler makes
    # one per literal, named for the literal's own bytes — and `$` is not legal
    # in a constant, so it cannot travel through the source channel at all.
    #
    # A consumer handed only the name has nothing to define, and defining
    # nothing is what left `undefined constant ::$Regex:...` at the end of a
    # build that had every declaration it needed. So the pattern and the flags
    # come too, and the consumer builds the constant under the name its object
    # code reads.
    #
    # Empty unless a body that travelled held a regex literal, which makes it
    # empty for every module built under iyi's prelude: a `.iyi` file has no
    # runtime `Regex` and its literals are refused where they are expanded.
    #
    # Settable alongside `object_code`, and for the same reason.
    property regexes : Array(RegexConst)

    # The class variables this module's object code refers to, as
    # `Owner::@@name`.
    #
    # `constants` asked of a global. A class variable's global is defined in
    # the main module, and a main module is the one part of a build that never
    # travels — so the methods that read one arrived as machine code referring
    # to a symbol nothing defined, and a module with a `@@seen` failed R-1's
    # own round trip.
    #
    # Two kinds of name are in here and the consumer treats them alike. One is
    # this module's own, whose declaration travels with its type in
    # `TypeDecl#class_vars`; the other is the library's — a shard that calls
    # `String#upcase` refers to `Unicode::@@upcase_ranges` — and the consumer
    # already has that declaration, having compiled the same library. Either
    # way what is owed is the same: the global, emitted.
    #
    # The declaration alone does not do it, which is why both exist. A
    # `@@cache : String? = nil` has its nil initialiser dropped before an
    # artifact is written, so the consumer read the declaration, made no
    # initialiser from it, and codegen emitted nothing.
    #
    # Settable alongside `object_code`, and for the same reason.
    property class_vars : Array(ClassVarRef)

    # Whether this module was compiled against Crystal's standard library
    # rather than iyi's prelude — `--crystal`.
    #
    # Recorded rather than inferred from `requires`, because a module can be
    # built with `--crystal` and require nothing, and it is still compiled
    # against a different `String`. Two libraries define types of the same
    # names with different layouts and different method symbols, so a program
    # cannot hold one module of each: the link would succeed on the names that
    # happen to agree and be wrong about the rest. Checked on import, beside
    # the version, the target and the flags (IV.5).
    property crystal_library : Bool

    # Under `--crystal`, the library files this module required, in the order
    # it required them.
    #
    # A module compiled against Crystal's library is compiled against the types
    # that library defines, and its object code refers to them by name — a type
    # id, a constant, a method symbol. The consumer defines those names, and it
    # can only define the ones its own program has. A module that required
    # `uri` and a consumer that did not left `URI::Error.class:type_id`
    # undefined at link time: a name from a library the consumer had never
    # heard of, in an object file it did not compile.
    #
    # So the requires travel with the module and the consumer replays them,
    # which makes the consumer's program a superset of the producer's. The
    # *numbering* is still the consumer's — that is what `TypeIds` is for — so
    # this adds types rather than importing anybody else's ids.
    #
    # Empty for a module built under iyi's own prelude, which has no `require`.
    property requires : Array(String)

    # IV.3's three hashes. See `Hashes`.
    #
    # Settable because they are computed *from* the rest of the artifact: the
    # interface hash is over the exports this record already carries, so it can
    # only be taken once they are in it.
    property hashes : Hashes

    def initialize(@module_name, @source_path, @compiler_version, @target_triple,
                   @flags, @imports, @usings = [] of String, @exports = Exports.empty,
                   @object_code = [] of ObjectUnit, @has_initialiser = false,
                   @mono_bodies = {} of String => String, @initialiser = "",
                   @type_ids = [] of String, @hashes = Hashes.empty,
                   @constants = [] of String, @macro_bodies = [] of String,
                   @requires = [] of String, @crystal_library = false,
                   @regexes = [] of RegexConst, @class_vars = [] of ClassVarRef,
                   @layouts = [] of {String, TypeLayout})
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

    # Second, right behind the header, because a build deciding what to rebuild
    # reads these and nothing else: the section table lets it stop here.
    sections << {Section::Hashes, encode_hashes(artifact)} unless artifact.hashes.empty?

    sections << {Section::Imports, encode_imports(artifact)}

    # With the imports, because it is the same question asked of the other
    # world: what has to be loaded before these declarations mean anything.
    unless artifact.requires.empty?
      sections << {Section::Requires, encode_requires(artifact)}
    end

    sections << {Section::Exports, encode_exports(artifact)}

    # Between the declarations and the machine code, which is where it belongs:
    # a front-end reader needs it and a linker does not.
    # Before the bodies, because a body may call one of them and a reader that
    # stops early should have the smaller thing.
    unless artifact.macro_bodies.empty?
      sections << {Section::MacroBodies, encode_macro_bodies(artifact)}
    end

    unless artifact.mono_bodies.empty?
      sections << {Section::MonoBodies, encode_mono_bodies(artifact)}
    end

    unless artifact.initialiser.empty?
      sections << {Section::Initialiser, encode_initialiser(artifact)}
    end

    # With the object code rather than with the declarations, because it is
    # about the object code: a front-end reader has nothing to link and so
    # nothing to number.
    unless artifact.type_ids.empty?
      sections << {Section::TypeIds, encode_type_ids(artifact)}
    end

    unless artifact.constants.empty?
      sections << {Section::Constants, encode_constants(artifact)}
    end
    # With the object code rather than with the declarations, for the reason
    # `TypeIds` sits here: a front-end reader has nothing to number, and so
    # nothing to lay out.
    unless artifact.layouts.empty?
      sections << {Section::Layouts, encode_layouts(artifact)}
    end

    # Right behind the names it completes, and read the same way: what a
    # consumer has to build before it can read them.
    unless artifact.regexes.empty?
      sections << {Section::Regexes, encode_regexes(artifact)}
    end

    unless artifact.class_vars.empty?
      sections << {Section::ClassVars, encode_class_vars(artifact)}
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
          file.write_bytes checksum(payload), FORMAT
        end
        sections.each { |(_, payload)| file.write payload }
      end
      File.rename temporary, path
    rescue ex
      File.delete?(temporary)
      raise ex
    end
  end

  # iyi: a section read is a section checked (format v19).
  private def self.verify(path : String, section : Section?, payload : Bytes, sum : UInt64) : Nil
    return if checksum(payload) == sum
    name = section ? section.to_s : "an unknown"
    raise Error.new("#{path}: the #{name} section is damaged, its checksum does " \
                    "not match what was written. Rebuild it with `--emit-iyimod`")
  end

  # The magic, the format version and the section table.
  private def self.read_table(file : IO, path : String) : Array({UInt16, UInt32, UInt64})
    magic = Bytes.new(MAGIC.size)
    file.read_fully?(magic) || raise Error.new("#{path} is too short to be a .iyimod")
    raise Error.new("#{path} is not a .iyimod") unless magic == MAGIC

    format_version = file.read_bytes(UInt32, FORMAT)
    unless format_version == FORMAT_VERSION
      raise Error.new("#{path} is .iyimod format v#{format_version}, this compiler writes v#{FORMAT_VERSION}")
    end

    count = file.read_bytes(UInt32, FORMAT)
    Array({UInt16, UInt32, UInt64}).new(count) do
      kind = file.read_bytes(UInt16, FORMAT)
      file.read_bytes(UInt16, FORMAT) # padding
      {kind, file.read_bytes(UInt32, FORMAT), file.read_bytes(UInt64, FORMAT)}
    end
  end

  # What a build needs to decide whether to read the rest of *path* (IV.3): the
  # header, the hashes, and the edges with what they were compiled against.
  #
  # Everything else is seeked past. That is the section table earning its keep
  # on the path it matters most: a staleness check that had to page in the
  # exports and the object code to answer would cost more than the analysis it
  # saves, and it runs for every module in the graph including the ones it is
  # about to decide are fine.
  record Summary,
    module_name : String,
    compiler_version : String,
    target_triple : String,
    flags : Array(String),
    hashes : Hashes,
    imports : Array(ImportEdge)

  def self.read_summary(path : String) : Summary
    File.open(path, "rb") do |file|
      table = read_table(file, path)

      header = nil
      hashes = Hashes.empty
      imports = [] of ImportEdge

      table.each do |(kind, length, sum)|
        section = Section.from_value?(kind)
        unless section == Section::Header || section == Section::Hashes || section == Section::Imports
          file.skip length
          next
        end

        payload = Bytes.new(length)
        file.read_fully?(payload) || raise Error.new("#{path} ends inside a section")
        verify(path, section, payload, sum)
        case section
        when Section::Header  then header = decode_header(payload)
        when Section::Hashes  then hashes = decode_hashes(payload)
        when Section::Imports then imports = decode_imports(payload)[:imports]
        end
      end

      unless header
        raise Error.new("#{path} has no header section")
      end

      Summary.new(header[:module_name], header[:compiler_version],
        header[:target_triple], header[:flags], hashes, imports)
    end
  rescue ex : Error
    raise ex
  rescue ex : IO::EOFError
    # iyi: a `.iyimod` is the one input here that nobody typed, and this
    # reader assumed it was one this compiler had written. Truncate one and
    # `skip` raised `IO::EOFError` with a stack trace, naming no file and
    # reading as a compiler bug rather than as a damaged file.
    raise Error.new("#{path} is truncated: it ends in the middle of a .iyimod")
  rescue ex
    raise Error.new("#{path} is not a readable .iyimod: #{ex.message} (#{ex.class}). " \
                    "It is damaged, or was written by something that is not this " \
                    "compiler; rebuild it with `--emit-iyimod`")
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
      table = read_table(file, path)

      header = nil
      imports = {imports: [] of ImportEdge, usings: [] of String}
      exports = Exports.empty
      object_code = [] of ObjectUnit
      mono_bodies = {} of String => String
      macro_bodies = [] of String
      initialiser = ""

      type_ids = [] of String
      constants = [] of String
      regexes = [] of RegexConst
      class_vars = [] of ClassVarRef
      requires = [] of String
      hashes = Hashes.empty
      layouts = [] of {String, TypeLayout}

      table.each do |(kind, length, sum)|
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
        verify(path, section, payload, sum)
        case section
        when Section::Header      then header = decode_header(payload)
        when Section::Imports     then imports = decode_imports(payload)
        when Section::Exports     then exports = decode_exports(payload)
        when Section::ObjectCode  then object_code = decode_object_code(payload)
        when Section::MonoBodies  then mono_bodies = decode_mono_bodies(payload)
        when Section::MacroBodies then macro_bodies = decode_macro_bodies(payload)
        when Section::Initialiser then initialiser = String.new(payload)
        when Section::TypeIds     then type_ids = decode_type_ids(payload)
        when Section::Constants   then constants = decode_constants(payload)
        when Section::Regexes     then regexes = decode_regexes(payload)
        when Section::ClassVars   then class_vars = decode_class_vars(payload)
        when Section::Requires    then requires = decode_requires(payload)
        when Section::Hashes      then hashes = decode_hashes(payload)
        when Section::Layouts     then layouts = decode_layouts(payload)
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
        object_code, header[:has_initialiser], mono_bodies, initialiser, type_ids,
        hashes, constants, macro_bodies, requires, header[:crystal_library],
        regexes, class_vars, layouts)
    end
  rescue ex : Error
    raise ex
  rescue ex : IO::EOFError
    # iyi: a `.iyimod` is the one input here that nobody typed, and this
    # reader assumed it was one this compiler had written. Truncate one and
    # `skip` raised `IO::EOFError` with a stack trace, naming no file and
    # reading as a compiler bug rather than as a damaged file.
    raise Error.new("#{path} is truncated: it ends in the middle of a .iyimod")
  rescue ex
    raise Error.new("#{path} is not a readable .iyimod: #{ex.message} (#{ex.class}). " \
                    "It is damaged, or was written by something that is not this " \
                    "compiler; rebuild it with `--emit-iyimod`")
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
    hashes = artifact.hashes
    unless hashes.empty?
      io.puts "hashes"
      io.puts "  interface      #{hashes.interface}"
      io.puts "  implementation #{hashes.implementation}"
      io.puts "  source         #{hashes.source}"
    end

    if artifact.imports.empty?
      io.puts "imports       (none)"
    else
      io.puts "imports"
      artifact.imports.each do |edge|
        if edge.interface.empty?
          io.puts "  #{edge.module_name}"
        else
          io.puts "  #{edge.module_name} — interface #{edge.interface}, implementation #{edge.implementation}"
        end
      end
    end

    io.puts "library       #{artifact.crystal_library ? "Crystal's standard library (--crystal)" : "iyi's prelude"}"

    unless artifact.requires.empty?
      io.puts "requires"
      artifact.requires.each { |name| io.puts "  #{name}" }
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

      # Named for what they are, because the dump renders an exported def and
      # an unexported one the same way and the difference is the whole point of
      # them being in a list of their own.
      unless exports.carried_functions.empty?
        io.puts "  # not exported, carried for the bodies that travel"
        exports.carried_functions.each { |signature| io.puts "  #{render_signature(signature)}" }
      end

      exports.types.each { |declaration| dump_type_declaration io, declaration, "  " }

      exports.impls.each do |record|
        io.puts "  #{render_impl_header(record)}"
        record.assoc_types.each { |(name, answer)| io.puts "    type #{name} = #{answer}" }
        record.methods.each { |signature| io.puts "    #{render_signature(signature)}" }
      end
    end

    macros = artifact.macro_bodies
    if macros.empty?
      io.puts "macros        (none)"
    else
      io.puts "macros"
      macros.each { |source| io.puts "  #{source.lines.first? || ""}" }
    end

    bodies = artifact.mono_bodies
    if bodies.empty?
      io.puts "mono bodies   (none)"
    else
      io.puts "mono bodies"
      bodies.keys.sort!.each { |key| io.puts "  #{key}" }
    end

    type_ids = artifact.type_ids
    unless type_ids.empty?
      io.puts "type ids"
      type_ids.each { |name| io.puts "  #{name}" }
    end

    constants = artifact.constants
    unless constants.empty?
      io.puts "constants"
      constants.each { |name| io.puts "  #{name}" }
    end
    layouts = artifact.layouts
    if layouts.empty?
      io.puts "layouts       (none)"
    else
      io.puts "layouts"
      layouts.each do |(name, layout)|
        io.puts "  #{name}: type id #{layout.type_id}, #{layout.alloc_size} bytes " \
                "(scan cap #{layout.scan_cap}), scan #{layout.scan_offsets}, " \
                "noscan #{layout.noscan_offsets}"
      end
    end

    # With the pattern, because the name is a digest: a reader looking at
    # `$Regex:5f2b…` in the list above has no way to tell which literal it is.
    class_vars = artifact.class_vars
    unless class_vars.empty?
      io.puts "class variables"
      class_vars.each do |ref|
        io.puts "  #{ref.name}#{ref.lazy ? " (through its read function)" : ""}"
      end
    end

    regexes = artifact.regexes
    unless regexes.empty?
      io.puts "regex constants"
      regexes.each { |regex| io.puts "  #{regex.name} = /#{regex.pattern}/ (#{regex.options})" }
    end

    object_code = artifact.object_code
    if object_code.empty?
      io.puts "object code   (none)"
    else
      io.puts "object code"
      object_code.each { |unit| io.puts "  #{unit.name} — #{unit.code.size} bytes" }
    end

    # Said out loud on every dump, because a reader has no way to tell a field
    # list that is absent from one that is empty.
    io.puts
    io.puts "note          format v#{FORMAT_VERSION} carries declarations,"
    io.puts "              signatures, field lists in declaration order, the"
    io.puts "              the constants and class variables this module's"
    io.puts "              own code reads, the macros and"
    io.puts "              bodies a consumer has to compile for itself, the"
    io.puts "              object code of this module's own non-generic types,"
    io.puts "              and the pointer maps of the types this module owns"
    io.puts "              (SPEC.md IV.2, GC_DESIGN.md Stage 1)."
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
      artifact.import_names.each { |name| io << "import " << name << '\n' }
    end

    # And the other world's, restated for the same reason and one more: a
    # signature here can name `URI::Params`, and the module's object code calls
    # into that library by name. The consumer has to have compiled it too, or
    # the link fails on a name from a library nobody in this program required
    # (IV.1g, `Requires`).
    unless artifact.requires.empty?
      io << '\n'
      artifact.requires.each { |name| io << "require " << name.inspect << '\n' }
    end

    # Inside the module, where the parser keeps a `using` — it resolves names
    # for this module's declarations and must not reach whoever reads them.
    unless artifact.usings.empty?
      io << '\n'
      artifact.usings.each { |directive| io << "using " << directive << '\n' }
    end

    exports = artifact.exports
    bodies = artifact.mono_bodies

    # First, because a macro has to be defined before the code that calls it is
    # read, and the bodies below are full of code that calls them.
    artifact.macro_bodies.each do |source|
      io << '\n' << source << '\n'
    end

    exports.functions.each do |signature|
      io << '\n'
      # A module's own `pub def` that takes a block ships its body, because the
      # consumer is what instantiates it — the block is the consumer's code.
      # The container is the module's own path.
      render_declaration io, signature, exported: true,
        body: bodies[mono_body_key(artifact.module_name, signature)]?
    end

    # And the ones it does not export, written as they were written: without
    # `pub`, so the consumer has them and cannot name them. They are here
    # because a body that travels may call one, and a block-taking one brings
    # its body along for the reason every travelling body does.
    exports.carried_functions.each do |signature|
      io << '\n'
      render_declaration io, signature,
        body: bodies[mono_body_key(artifact.module_name, signature)]?
    end

    exports.types.each do |declaration|
      io << '\n'
      render_type_declaration io, declaration, bodies
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
  # *check_block* is R-2's rule, and it applies to what another module reads.
  # A type the module keeps to itself is read by nobody, so its methods travel
  # without it — they are there for a body that travels to typecheck against,
  # not for anyone to call.
  def self.signature(a_def : Def, check_block : Bool = true) : Signature
    if check_block
      check_block_annotated a_def
      check_types_written a_def
    end

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

  # iyi: R-2 itself, asked in two places.
  #
  # This one is called when the artifact is written, which is where an
  # unchecked export does its damage, and again from the top-level visitor when
  # a module-level `pub def` is declared, which is where the author is. Asking
  # only at the artifact meant `pub def twice(x)` compiled all day and failed
  # the first time somebody packaged the module — a rule of the language
  # reported as a packaging error.
  #
  # "Everything a module exports carries full parameter and return types" was a
  # rule the format assumed and nothing checked. What that cost is paid by the
  # consumer rather than by the author: `pub def greet(name)` compiles, the
  # artifact records `def greet(name)`, and a build that reads it types the call
  # from a return type that is not there. The producer emitted
  # `greet<String>:String` and the consumer asks for `greet<String>:Nil`, so the
  # module's own build is fine and somebody else's fails at the linker, naming a
  # mangled symbol and no rule.
  #
  # `initialize` is exempt: it answers the type it is defined on, and writing
  # that down would be the one annotation a reader cannot get wrong. So is a
  # setter, which answers what it was handed.
  def self.check_types_written(a_def : Def) : Nil
    # A method in an `impl` is not asked twice. The trait already wrote the
    # types down (`abstract def show : String`), the impl is checked against
    # them, and a consumer types the call from the trait rather than from here.
    return if a_def.iyi_from_impl?

    untyped = a_def.args.reject(&.restriction).map(&.name)
    unless untyped.empty?
      a_def.raise <<-MSG
        `#{a_def.name}` is exported and does not say what #{untyped.size == 1 ? "`#{untyped.first}` is" : "#{untyped.map { |name| "`#{name}`" }.join(", ")} are"}

        R-2 asks an exported signature for full types, so that a module reading \
        it from a `.iyimod` infers nothing. Nothing here can be recovered from \
        the body, because the body is what stays behind.

        Annotate the parameter, or leave the def unexported.
        MSG
    end

    return if a_def.return_type
    return if a_def.name == "initialize"
    return if a_def.name.ends_with?('=')

    a_def.raise <<-MSG
      `#{a_def.name}` is exported and does not say what it returns

      R-2 asks an exported signature for full types. A consumer types a call to \
      this from the return type alone, since the body stays in this module: \
      without one it infers `Nil`, and the symbol it then asks the linker for is \
      not the symbol this module emitted.

      Annotate the return type, or leave the def unexported.
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
      #
      # It is marked as the other thing instead, because the type it is on came
      # from the artifact and codegen reads that as "somebody else's machine
      # code". True of the type's ordinary methods and not of this one.
      unless node.body.is_a?(Nop)
        node.iyi_body_travelled = true
        return false
      end

      node.iyi_from_artifact = true
      node.uses_block_arg = true if node.block_arg.try(&.restriction)
      false
    end

    # Every path in this text was rendered from a type the producing build had
    # resolved, and some of them name what the module keeps to itself: a
    # carried type's field is `Array(Router::Route)` and `Route` is declared
    # `private`. Marked so the lookup may reach it — R-2b governs what another
    # module writes, and this is the module's own declaration arriving.
    def visit(node : Path)
      node.iyi_from_artifact = true
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

  # One type declaration in `mod dump`, and the types declared inside it.
  #
  # The visibility is shown, because "carried and unreachable" is a thing a
  # reader of this file has to be able to tell from "carried and exported".
  private def self.dump_type_declaration(io : IO, declaration : TypeDecl, indent : String) : Nil
    prefix = declaration.visibility.empty? ? "" : "#{declaration.visibility} "
    io.puts "#{indent}#{prefix}#{render_type_header(declaration)}"
    return if declaration.kind == "alias"

    inner = indent + "  "
    declaration.macros.each { |source| io.puts "#{inner}#{source.lines.first? || ""}" }
    declaration.assoc_types.each { |name| io.puts "#{inner}type #{name}" }
    declaration.fields.each { |(name, type)| io.puts "#{inner}#{name} : #{type}" }
    declaration.class_vars.each do |(name, type, value)|
      io.puts "#{inner}#{name} : #{type}#{value.empty? ? "" : " = #{value}"}"
    end
    declaration.types.each { |nested| dump_type_declaration io, nested, inner }
    declaration.methods.each { |signature| io.puts "#{inner}#{render_signature(signature)}" }
  end

  # One type declaration, and the types declared inside it.
  #
  # The visibility is written back as it was written: a type carried without
  # `pub` is declared here and reachable from nowhere, which is what it is when
  # the module is read from source rather than from this file. Nesting is kept
  # for the same reason — a nested type belongs to its container, and iyi has
  # no way to reopen the container to add one later.
  def self.render_type_declaration(io : IO, declaration : TypeDecl,
                                   bodies : Hash(String, String), indent = "") : Nil
    io << indent
    io << declaration.visibility << ' ' unless declaration.visibility.empty?
    io << render_type_header(declaration) << '\n'

    # An alias is the whole declaration, and there is nothing to close: it
    # names a type rather than declaring one.
    return if declaration.kind == "alias"

    inner = indent + "  "

    # Before everything the type declares, because a macro is read before it is
    # called and what it is called from is below it.
    declaration.macros.each do |source|
      source.each_line { |line| io << inner << line << '\n' }
    end

    declaration.assoc_types.each { |name| io << inner << "type " << name << '\n' }

    # Before the methods, where they are written and where a reader looks for
    # them. They are also what a `def initialize` with no body leaves
    # unassigned, which is why they arrive declared rather than inferred.
    declaration.fields.each { |(name, type)| io << inner << name << " : " << type << '\n' }

    # A class variable is a global, and this line is what makes the consumer
    # define one. Written as a declaration with its value rather than as a bare
    # assignment so that a variable with no initialiser still arrives typed —
    # a lazy `class_getter` has its `||=` in the method that travels as machine
    # code, and all that is owed here is the global it assigns to.
    declaration.class_vars.each do |(name, type, value)|
      io << inner << name << " : " << type
      io << " = " << value unless value.empty?
      io << '\n'
    end

    # An enum's members, which are what an enum is. `Small = 0` rather than
    # `Small : Int32`: the number is the member, and a consumer that read it as
    # a field would have a type where a value belongs.
    declaration.members.each { |(name, value)| io << inner << name << " = " << value << '\n' }

    declaration.types.each { |nested| render_type_declaration io, nested, bodies, inner }

    declaration.methods.each do |signature|
      render_declaration io, signature, indent: inner,
        body: bodies[mono_body_key(declaration.name, signature)]?
    end
    io << indent << "end\n"
  end

  # A type's declaration line — `struct List(T)`, `trait Ord : Eq`.
  #
  # The kind loses its `generic ` prefix, which is how a `Iyi::Type`
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

      # `alias Handler = Context -> String`. The right-hand side is the type
      # the alias resolved to rather than the text it was written as, for the
      # reason a field's type is: this file is read where the module was not,
      # and a name that resolved there may not resolve here.
      io << " = " << declaration.value if declaration.kind == "alias"

      # An enum's base type, written the way it is declared. The same field as
      # an alias's right-hand side, and for the same reason: it is the type this
      # declaration is defined in terms of.
      io << " : " << declaration.value if declaration.kind == "enum" && !declaration.value.empty?
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
    io.write_byte(artifact.crystal_library ? 1_u8 : 0_u8)
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
    crystal_library = io.read_byte == 1_u8
    {module_name: module_name, source_path: source_path,
     compiler_version: compiler_version, target_triple: target_triple, flags: flags,
     has_initialiser: has_initialiser, crystal_library: crystal_library}
  end

  private def self.encode_requires(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_strings io, artifact.requires
    io.to_slice
  end

  private def self.encode_imports(artifact : Artifact) : Bytes
    io = IO::Memory.new
    edges = artifact.imports
    io.write_bytes edges.size.to_u32, FORMAT
    edges.each do |edge|
      write_string io, edge.module_name
      write_string io, edge.interface
      write_string io, edge.implementation
    end
    write_strings io, artifact.usings
    io.to_slice
  end

  private def self.decode_requires(payload : Bytes) : Array(String)
    read_strings IO::Memory.new(payload)
  end

  private def self.decode_imports(payload : Bytes)
    io = IO::Memory.new(payload)
    edges = Array(ImportEdge).new(io.read_bytes(UInt32, FORMAT)) do
      ImportEdge.new(read_string(io), read_string(io), read_string(io))
    end
    {imports: edges, usings: read_strings(io)}
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

  private def self.encode_macro_bodies(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_strings io, artifact.macro_bodies
    io.to_slice
  end

  private def self.decode_macro_bodies(payload : Bytes) : Array(String)
    read_strings(IO::Memory.new(payload))
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

  private def self.encode_hashes(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_string io, artifact.hashes.interface
    write_string io, artifact.hashes.implementation
    write_string io, artifact.hashes.source
    io.to_slice
  end

  private def self.decode_hashes(payload : Bytes) : Hashes
    io = IO::Memory.new(payload)
    Hashes.new(read_string(io), read_string(io), read_string(io))
  end

  private def self.encode_constants(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_strings io, artifact.constants
    io.to_slice
  end

  private def self.decode_constants(payload : Bytes) : Array(String)
    read_strings(IO::Memory.new(payload))
  end

  private def self.encode_class_vars(artifact : Artifact) : Bytes
    io = IO::Memory.new
    refs = artifact.class_vars
    io.write_bytes refs.size.to_u32, FORMAT
    refs.each do |ref|
      write_string io, ref.name
      io.write_byte(ref.lazy ? 1_u8 : 0_u8)
    end
    io.to_slice
  end

  private def self.decode_class_vars(payload : Bytes) : Array(ClassVarRef)
    io = IO::Memory.new(payload)
    Array(ClassVarRef).new(io.read_bytes(UInt32, FORMAT)) do
      ClassVarRef.new(read_string(io), io.read_byte == 1_u8)
    end
  end

  private def self.encode_regexes(artifact : Artifact) : Bytes
    io = IO::Memory.new
    regexes = artifact.regexes
    io.write_bytes regexes.size.to_u32, FORMAT
    regexes.each do |regex|
      write_string io, regex.name
      write_string io, regex.pattern
      io.write_bytes regex.options, FORMAT
    end
    io.to_slice
  end

  private def self.decode_regexes(payload : Bytes) : Array(RegexConst)
    io = IO::Memory.new(payload)
    Array(RegexConst).new(io.read_bytes(UInt32, FORMAT)) do
      RegexConst.new(read_string(io), read_string(io), io.read_bytes(UInt32, FORMAT))
    end
  end

  private def self.encode_type_ids(artifact : Artifact) : Bytes
    io = IO::Memory.new
    write_strings io, artifact.type_ids
    io.to_slice
  end

  private def self.decode_type_ids(payload : Bytes) : Array(String)
    read_strings(IO::Memory.new(payload))
  end

  private def self.encode_layouts(artifact : Artifact) : Bytes
    io = IO::Memory.new
    layouts = artifact.layouts
    io.write_bytes layouts.size.to_u32, FORMAT
    layouts.each do |(name, layout)|
      write_string io, name
      io.write_bytes layout.type_id, FORMAT
      io.write_bytes layout.alloc_size, FORMAT
      io.write_bytes layout.scan_cap, FORMAT
      io.write_bytes layout.scan_offsets.size.to_u32, FORMAT
      layout.scan_offsets.each { |offset| io.write_bytes offset, FORMAT }
      io.write_bytes layout.noscan_offsets.size.to_u32, FORMAT
      layout.noscan_offsets.each { |offset| io.write_bytes offset, FORMAT }
    end
    io.to_slice
  end

  private def self.decode_layouts(payload : Bytes) : Array({String, TypeLayout})
    io = IO::Memory.new(payload)
    Array({String, TypeLayout}).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      type_id = io.read_bytes(Int32, FORMAT)
      alloc_size = io.read_bytes(UInt32, FORMAT)
      scan_cap = io.read_bytes(UInt32, FORMAT)
      scan_offsets = Array(UInt16).new(io.read_bytes(UInt32, FORMAT)) do
        io.read_bytes(UInt16, FORMAT)
      end
      noscan_offsets = Array(UInt16).new(io.read_bytes(UInt32, FORMAT)) do
        io.read_bytes(UInt16, FORMAT)
      end
      {name, TypeLayout.new(type_id, alloc_size, scan_cap, scan_offsets, noscan_offsets)}
    end
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

    write_type_declarations io, artifact.exports.types

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

    write_signatures io, artifact.exports.carried_functions

    io.to_slice
  end

  # Recursive, because a type's declarations are types: the nesting a module
  # wrote is the nesting a consumer has to read back, and iyi cannot reopen a
  # container to add one afterwards.
  private def self.write_type_declarations(io : IO, types : Array(TypeDecl)) : Nil
    io.write_bytes types.size.to_u32, FORMAT
    types.each do |declaration|
      write_string io, declaration.name
      write_string io, declaration.kind
      write_string io, declaration.value
      write_string io, declaration.visibility
      write_strings io, declaration.type_parameters
      write_strings io, declaration.assoc_types
      write_strings io, declaration.supertraits
      write_pairs io, declaration.fields
      write_pairs io, declaration.members
      write_triples io, declaration.class_vars
      write_strings io, declaration.macros
      write_signatures io, declaration.methods
      write_type_declarations io, declaration.types
    end
  end

  private def self.read_type_declarations(io : IO) : Array(TypeDecl)
    Array(TypeDecl).new(io.read_bytes(UInt32, FORMAT)) do
      name = read_string(io)
      kind = read_string(io)
      value = read_string(io)
      visibility = read_string(io)
      parameters = read_strings(io)
      assoc_types = read_strings(io)
      supertraits = read_strings(io)
      fields = read_pairs(io)
      members = read_pairs(io)
      class_vars = read_triples(io)
      macros = read_strings(io)
      methods = read_signatures(io)
      TypeDecl.new(name, kind, parameters, assoc_types, supertraits, fields, methods,
        visibility, read_type_declarations(io), value, macros, members, class_vars)
    end
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

    types = read_type_declarations(io)

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

    Exports.new(functions, types, impls, read_signatures(io))
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

  private def self.write_triples(io : IO, values : Array({String, String, String})) : Nil
    io.write_bytes values.size.to_u32, FORMAT
    values.each do |(first, second, third)|
      write_string io, first
      write_string io, second
      write_string io, third
    end
  end

  private def self.read_triples(io : IO) : Array({String, String, String})
    Array({String, String, String}).new(io.read_bytes(UInt32, FORMAT)) do
      {read_string(io), read_string(io), read_string(io)}
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
