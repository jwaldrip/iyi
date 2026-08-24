# Changelog

## Unreleased

### Added

- **The type-id list is the import graph, so it cannot be filtered.** Two
  separate failures at kemal's scale came from one list being less than whole.

  A module's type id is its *metaclass's*: `Backtracer::Backtrace::Parser:Module`
  is how a module's metaclass prints. Carrying the instance and stopping there
  defined `…::Parser:type_id` for object code that wanted
  `…::Parser:Module:type_id`, because the walk that numbers metaclasses reaches
  only classes. The consumer numbers the metaclass too now.

  And the list had been filtered to the kinds a consumer could not number for
  itself, leaving plain classes out on the reasoning that the consumer has them
  already. It has them only if it *imports the module that declares them* — and
  that import edge is derived from this very list. `Kemal` numbers
  `ExceptionPage::Styles`, the name was filtered, no edge was added, and the
  consumer never read `exception_page` at all. Whole, the list costs `Kemal`
  642 names where it carried 303, and a name is a string.

  The metaclass half takes the kemal consumer from eight undefined symbols to
  six. The import-edge half is not counted the same way: with the edge added,
  `ExceptionPage::Styles` stops being a mangled symbol at link time and becomes
  a refusal that names it, which arrives *before* the linker — so the five
  behind it are no longer measured. Both the refusal and
  `exception_page` filling with 0 units are the same item: a class-rooted
  namespace colliding with its own module wrapper, in Part V item 12.

- **What a generic declares is kept, even though the generic is not.** The keep
  file skips a generic type — rightly, since `uninitialized Holder(T)` is not a
  thing anybody can write — and skipped everything it declares along with it.
  Those have object-code units in the artifact all the same: `Radix::Tree(T)`
  holds two error classes carrying 1.3 MB each, radix's keep file was **empty**,
  and the only `to_s` symbols it emitted were the ones radix's own code
  happened to reach — `to_s<IO::Memory>`, `to_s<IO::FileDescriptor>` — while
  the boundary declared `io : IO` and a consumer asked for the declared
  `to_s<IO+>`.

  A nested type is not parameterised by its container unless it says so, so
  recursing past the generic is all it took. The kemal consumer goes from ten
  undefined symbols to eight, and `bench/bind_roundtrip.sh` carries a
  non-generic class inside a generic one and prints the symbol its declaration
  produced.

- **A variable can be read wider than the slot that holds it, and that is a
  widening.** Inside a dispatch arm the slot holds the arm's concrete type
  while the read wants the type the boundary declared — an `IO` parameter read
  as `IO+` — and `visit(Var)` called `downcast` on it:
  `BUG: trying to downcast IO+ <- IO::Memory`. It is the same correction the
  call arguments already carried, one level in.

  **Which direction it is cannot be asked of `implements?`.** Answering it that
  way broke the compiler's own build: a virtual type implements its base, so
  `Iyi::Def+` held in a slot and read as `Iyi::Def` looked like a widening and
  is the opposite. What separates them is shape — a union or a virtual type is
  the wider thing — so a widening is reading a *concrete* slot as one of those,
  and nothing else is.

  With it the kemal consumer reaches the linker rather than aborting in
  codegen. An earlier entry said that consumer had zero undefined symbols; that
  was not a measurement — the build was dying before the linker ran. It links
  now and waits on ten.

- **Inheritance crosses a boundary.** `TypeDecl` had no field for the `<`, so a
  bound `Derived < Base` arrived without its base and without the fields it
  inherits — a class's own field list is only its own — and the consumer said
  `undefined method 'tag' for Shard::Derived`. The edge travels now, and the
  declarations are written superclass-first so `class Derived < Base` resolves.

  The edge alone left three more, each a place that had only ever seen a class
  with nothing under it. **A method is keyed on the type that defines it**: a
  boundary has one symbol per method where an ordinary build makes one per
  receiver, which is the mirror of the rule the parameter side already carries.
  That symbol is keyed on the class's **virtual form**, because a value of a
  class something inherits from is held as one — the symbol is
  `*Shard::Base+@Shard::Base#tag`. And a class with subclasses has a **second
  unit**, `Shard::Base+`, holding the methods reached through that form; the
  artifact was carrying neither it nor its callees.

  **The undefined symbol was the safe half of the bug.** A match against a
  virtual type compares an id against the *range* its subclasses occupy, and
  ids are assigned by walking that same tree — so a consumer missing an edge
  numbers the tree differently. Defining the function anyway would answer
  `is_a?` wrongly and link cleanly.

  Two more followed from more of a real shard crossing: a type read from a
  `.iyimod` is exempt from the "not initialized in all of the 'initialize'
  methods" check on the branch where the field's type does not include `Nil`,
  as it already was on the other; and a restriction can be virtual while the
  value is concrete — an `IO` parameter matched against `IO+` — which is
  answered with the range rather than a single type id.

  A consumer of kemal's four bound shards goes from **11 undefined symbols to
  10**, and the three the superclass edge was built for — `~match` against
  `HTTP::StaticFileHandler+` and two like it — are among the ones gone.
  `bench/bind_roundtrip.sh` carries a base, a subclass, an inherited method and
  an overridden one.

- **The unions a bound module matches against travel.** `is_a?` against a union
  or a virtual type compiles to `~match<T>`, a function that compares a type id
  against a *range* of the program's own numbering — so it lives in the main
  module, which does not travel, and it cannot be carried as code either: a
  copy compiled by the producer would compare the consumer's ids against the
  producer's numbers and answer wrongly with no symptom.

  A virtual one the consumer could already find for itself, by taking the
  virtual form of every class it numbers. A union it could not: no walk over a
  program arrives at `(Char | Iyi::Keyword | String | Nil)`, which is a type
  kemal's code formed and a consumer of kemal's never would. A `MatchTypes`
  section carries the names and the consumer builds each function with its own
  numbering, the same arrangement `TypeIds` already has. A consumer of kemal's
  four boundaries goes from **22 undefined symbols to 11**.

  `bench/bind_roundtrip.sh` matches against a union its consumer never forms,
  and prints the carried name so the line cannot quietly stop testing anything.

- **A module crosses a boundary, and what was inside it comes with it.**
  `crystal tool bind` recorded a module as a "nested namespace skipped" and
  carried nothing for it. Two failures at kemal's scale were the same failure:
  `Backtracer::Backtrace::Parser` is a module the object code *numbers* and a
  consumer could not name, and `Kemal::Exceptions::CustomException` and three
  like it had object-code units in the artifact — 1.8 MB each — with no
  declaration anywhere, because the walk stopped at `Exceptions` and everything
  under it went with it.

  A module travels as a declaration now, with its nested types, its methods and
  its class variables. Without `pub`: iyi's `pub` takes a def, a class, a
  struct, a trait and an enum, and what a namespace owes is that the things
  *inside* it can be named, each carrying its own visibility. A consumer of
  kemal's four boundaries goes from **40 undefined symbols to 22**, and
  `bench/bind_roundtrip.sh` keeps a nested module with a class and a
  module-level `def self.` in it.

- **A module's own class variables travel, and so do the type ids of modules.**
  Running kemal's four shards through boundaries in dependency order —
  `backtracer` → `radix` → `exception_page` → `kemal` — found both. A
  `TypeDecl` holds a type's class variables and a module is not a `TypeDecl`,
  so `module Backtracer; class_getter(configuration)` left
  `Backtracer::configuration` undefined at the end of a build that had every
  one of that shard's types and their class variables. `Exports` holds the
  module's own now.

  And type ids are handed out by walking `Object`'s subclasses, which reaches a
  class and neither an enum nor a module — `Backtracer::Backtrace::Parser` was
  numbered nowhere in a consumer that never mentions it. `TypeIds` carries
  those too, which turns the link error into the refusal that names the module
  and the type it cannot reach.

  `bench/bind_roundtrip.sh` keeps a class variable on the module root as well
  as on the class under it.

- **A bound shard can match a regex, which took two more holes than the
  constant did.** With the pattern crossing and the class variables crossing, a
  `--crystal` consumer of a shard that *matched* still ended on
  `undefined symbol: *Regex::PCRE2::current_jit_stack` and
  `Regex::MatchOptions:type_id`. Both read as the copy rule failing to bring a
  library method along, and both were something else — `nm` on the unit shows
  the accessor was copied.

  `@@current_jit_stack` is `@[ThreadLocal]`, and a thread-local global is read
  through a `noinline` function that hands back its address rather than
  directly, because LLVM would hoist the address out of the thread. That
  function is the main module's, and a main module does not travel. It is the
  third thing a class variable owes, after the global and the read function.

  `Regex::MatchOptions` is an enum, and "a program defines every type id" means
  every id it has *handed out*. Ids come from walking `Object`'s subclasses,
  which reaches a class and not an enum — an enum takes its id from the first
  code that asks, and a consumer that never mentions it never asks. `TypeIds`
  carries the enums a unit numbers, beside the generic instances it already
  carried, and the two are missing for opposite reasons: an instantiation does
  not exist until it is named, an enum exists and is unnumbered.

  `bench/bind_regex_identity.sh` matches with its patterns now instead of only
  naming them, so each shard's literal is checked against text the other one's
  would reject.

- **A class variable crosses a boundary, which nothing had ever carried.** A
  class variable is a global. The methods that read one travel as a module's
  machine code and refer to it by symbol, and the global itself is defined in
  the main module — the one part of a build that never travels. Nothing in the
  format mentioned class variables at all, so R-1's own claim was false for any
  module that had one, in iyi's own language: build a module with a
  `@@seen : Int32 = 0`, delete its source, build again from the artifact, and
  the link ends on `undefined symbol: App::Counter::Tally::seen`.
  `bench/samples_roundtrip.sh` is the gate for exactly that claim and passed,
  because none of the six samples has a class variable.

  `TypeDecl` carries the declaration now — name, resolved type, and the
  initialiser as written — the way `fields` already do, one level up. That is
  what a module's own needs, and a bound shard's too.

  It is not enough alone, and `@@cache : String? = nil` is the case that says
  so: a nil initialiser assigns nothing, so it is dropped before the artifact
  is written, and the consumer that read the declaration made no initialiser
  from it and emitted no global. So a `ClassVars` section carries the names a
  unit's object code refers to and the consumer defines each. That second
  channel is also all a class variable of *Crystal's* library needs — the
  consumer has the declaration already, having compiled the same library, and
  a bound shard calling `String#upcase` was left without
  `Unicode::upcase_ranges`.

  **The global is not the whole debt, and the consumer cannot work out the
  rest.** A class variable with a live initialiser is read through
  `~Owner::name:read`, a main-module function that initialises on first use;
  one without is read straight off the global. Which a unit emitted is the
  producer's fact, so the section carries a flag beside each name. Both guesses
  were tried and each breaks a different world: assume the direct form and a
  `--crystal` build leaves `~Exception::CallStack::skip:read` undefined, which
  `bench/bind_roundtrip.sh` caught; assume the lazy form and an iyi-prelude
  program dies on `BUG: __crystal_once is not defined`, because that prelude
  has no `__crystal_once` and nothing under it ever takes the branch.

  **The value is caught before the compiler rewrites it.** The initialiser
  travels as source, and the node a class variable holds is not that source by
  the time an artifact is written — `CleanupTransformer` has replaced it with
  the literal's expansion. `@@nums = [1, 2, 3]` reached the format as five
  statements over three temporaries, and the consumer said `read before
  assignment to local variable '__temp_2'`.

- **A regex literal's constant is named after the literal, and what it was made
  from crosses a boundary.** The compiler turns a regex literal into a
  program-level constant, and the name it invented was the order the literal
  was met in: `$Regex:0`. That name reaches the linker — a unit reading the
  constant refers to `~$Regex:0:const_read` — and encounter order is not an
  identity two programs share. A consumer of a bound shard failed on
  `undefined constant ::$Regex:0`, and the obvious fix, skipping such names,
  was worse than the bug: the producer's object code still referred to the
  mangled name, and whichever constant the consumer had numbered zero would
  have satisfied it. A different pattern, silently.

  The name is `$Regex:` and a digest of the pattern and the flags now, so it
  means the same thing in a program that never compiled this source, and two
  modules that wrote the same literal share one constant rather than defining
  two. `$` still keeps it out of reach of anything anybody can write.

  A digest cannot be read backwards, so the pattern travels too, in a
  `Regexes` section beside the names in `Constants` — it cannot go through the
  source channel, because `$` is not legal in a constant and `Exports` is
  parsed text. The consumer builds the constant with the same `Regex.new` call
  the expander builds for a literal met in source, and from there it is
  ordinary: typed when read, initialised where read.

  **The name is the load-bearing half, and the channel alone looks like it
  works.** With the channel in and encounter-order naming restored, two bound
  shards holding one literal each both wrote `$Regex:0`, and the second shard
  matched against the first one's pattern with nothing raised and exit 0.
  `bench/bind_regex_identity.sh` is the gate: it takes two boundaries, because
  one can be wrong about the name and still right about the pattern.

- **A real shard is installed, built against and asked for two pages every
  build.** `bench/shard_serves.sh` takes the README's headline example
  literally: `require "kemal"` in an `.iyi` file, built `--crystal`, serving.
  Nothing here checked it. The samples cannot — none of them requires a shard,
  which is the point of the example — and CI's tarball job builds a *synthetic*
  shard against `crystal/syntax_highlighter`, which proves the library ships
  whole and cannot prove that a real shard's macros parse, that its route
  blocks compile, or that the thing answers.

  It reaches the network, which no other gate here does, and the shard is
  pinned at 1.12.0 so it fetches one version rather than today's. Two routes,
  because a single static string would pass with the router never running; the
  second reads a URL parameter, so the answer is right only if the request
  reached the block the shard's macros defined.

- **A bound shard is built from its boundary, linked and run every build.**
  `bench/bind_roundtrip.sh` is `samples_roundtrip.sh`'s question asked of the
  other kind of artifact: object code that is a shard's, declarations that
  `crystal tool bind` wrote, and a `--crystal` consumer. It binds, fills the
  units, builds the same program both ways, runs both and compares.

  III.6 rule 1 names two failures for a boundary whose signatures are wrong —
  an undefined symbol, or a call returning something of another type — and
  `spec/compiler/bind_spec.cr` reaches neither, because it reads declarations
  back and never links. That was written down as a deliberate limit. Nothing
  covered it, and the first thing this gate did was fail:

  ```
  ld.lld: error: undefined symbol: *Shard::Part#wider:(String | Nil)
  ```

  **And it found the same question on the other side of the arrow.**
  `def discards(io : IO)` is monomorphised on what it is passed, so the keep
  file emitted `discards<IO>` and a consumer handing it `STDOUT` asked for
  `discards<IO::FileDescriptor>`. Both answers that suggest themselves are bad:
  instantiating for every concrete subtype is the whole-program work an
  artifact exists to avoid, and refusing such methods costs real surface —
  `JSON` has 10 of 180 declarations taking an `IO`, `YAML` 10 of 193, `URI` 7
  of 55, counting only `IO`.

- **A call to a declaration read from a `.iyimod` is keyed on the parameter as
  declared, not on what the call site passes.** One line of a consumer said
  which answer the gap above wanted: `part.discards(STDOUT)` failed to link and
  `part.discards(STDOUT.as(IO))` linked and ran. The symbol was callable the
  whole time; the call was reading past the declaration.

  Keying on the argument is right everywhere the body is present to be compiled
  once per argument type. A declaration from an artifact has no body and
  exactly one symbol, so the parameter as written is what the call is keyed on
  and the argument is widened to it — the conversion `.as(IO)` was performing by
  hand. Getting the direction backwards says so plainly:
  `BUG: trying to downcast IO+ <- IO::FileDescriptor`, which is `downcast`
  being handed a widening. Nothing is refused and nothing is instantiated per
  subtype.

- **`pub enum`, and an enum crosses a boundary.** iyi took an `enum` already —
  the language has one and the compiler makes the type — but `pub` did not, so a
  module could declare one and never hand it out. It does now, and
  `crystal tool bind` writes the enum's members with the integer they are
  numbered on, read from what the compiler assigned rather than renumbered: the
  object file a consumer links is what gave them their numbers. An earlier note
  said iyi had no `enum` at all, which came from grepping the prelude and was
  wrong about the language.

- **A private type travels as private.** `JSON::PullParser` holds an
  `Array(ObjectStackKind)` and its object code numbers
  `Pointer(ObjectStackKind)`, so a consumer has to *number* a type it must never
  be able to *write*. Declaring it without `pub` is exactly that, and R-2b keeps
  the name unreachable. Dropping such types was the first answer and only the
  linker said otherwise.

- **A rebuild of a type declaration carries all of it.** Pruning and renaming
  both reconstructed a `TypeDecl` and left `value` and `macros` behind, which is
  how an alias lost its right-hand side and, once enums arrived, how one lost
  its members.

- **`crystal tool bind` asks what the consumer of a bound shard can name, which
  is not what it had been asking.** `nameable?` decides every count this tool
  prints, and it asked what an *iyi-prelude* program could name — a program that
  cannot consume one of these artifacts at all, because the units number
  `Pointer(LibUnwind::Exception)` whatever the shard does. The consumer is a
  `--crystal` program, which has Crystal's library, and now the shard's requires
  besides. Read from where each type was written rather than from a list.

  The surface had been reading low throughout. Without binding anything first:
  `JSON` 168 → **181** signatures and 13 → **0** waiting, `YAML` 166 → **194**
  and 32 → **0**, `URI` 48 → **55** and 9 → **0**. `Kemal` goes from 27 types
  carrying 65 methods to **34 carrying 148**, and `Kemal::Route`,
  `RouteDefinition`, `FileUpload` and three more stop being refused for naming
  types their actual consumer would have.

  Two things had to follow. A top-level name of Crystal's is written `::Log`,
  because an artifact's declarations are rendered inside their own module and
  `Kemal::Log` is a constant that would shadow it. And a generic carries the
  types nested inside it, which is how `Kemal::LRUCache::Node(K, V)` went
  missing while `LRUCache` travelled.

- **A bound shard's requires travel, and so does a dependency that only its
  type ids show.** A unit numbers the types its own `require`s brought in —
  `Radix` reaches `Hash(String, HTTP::Cookie)` — and a consumer whose prelude is
  Crystal's still does not have every file of it, so `require "http/cookie"`
  goes in the artifact. Crystal's only: a require that resolved into somebody
  else's `lib` is another shard, and replaying it would have the consumer
  compile from source the thing an artifact exists to spare it.

  The other half is an import edge nobody could see. `Kemal` names no `Radix`
  type in any declaration and its object code refers to
  `Array(Radix::Node(...))`, so a consumer that imported `kemal` had never heard
  of `radix`. The build that fills the object code reads the boundaries beside
  it and adds the edge, because only that build knows the type ids — `tool bind`
  and this are different processes.

- **A generic type crosses a boundary.** Its methods exist once per
  instantiation and the instantiations belong to whoever writes them — a
  consumer that writes `Holder(Float64)` needs a method the producer never made
  — so what travels is the declaration with its type parameters and the
  *source* of its methods, in `MonoBodies`, which is the answer IV.2 already
  names and `crystal tool bind` was not using. `new` stays out: it is
  synthesized from `initialize`, so a consumer makes its own and a carried one
  would meet it at the linker.

  A generic travels even with no methods to carry, because a consumer may need
  only to *name* it: `Kemal` refers to `Array(Radix::Node(...))` and calls no
  `Node` method. `Radix` carries three types where it carried none.

  What a generic's methods must have is a written return type. The trick that
  rescues an ordinary method — instantiate it on purpose and read what comes
  back — has no single answer when the owner is generic, so 20 of `Radix`'s 33
  methods stay behind.

- **A harness for what a consumer pays for a shard** (`bench/bind_speed.py`),
  from its source and from its boundary, at three sizes. A boundary pays once
  compiling the shard is a real share of the build — near ten thousand lines
  here — and costs a little below that: 2,167 lines costs 2%, 10,087 saves 9%,
  29,767 saves 11%.

  It could not be asked of `Kemal`, which cannot be bound: its object code
  numbers `Array(Radix::Node(...))`, a generic instance from another shard, and
  a generic travels as bodies rather than declarations. What `tool bind` says
  about `Kemal` stands on its own — 254 public methods, 93.3% needing no human,
  31 units of object code.

- **A private constant is not handed out.** The keep file read
  `Kemal::FilterHandler::WILDCARD_PATHS` through a generated accessor, which is
  what the shard's own compiler refuses. It still travels in the artifact's
  initialiser, because *defining* one is not *reading* it and the object code
  refers to it either way.

- **A build that fills a boundary does not link.** The keep file is not a
  program anybody runs — it exists so codegen emits the methods a consumer will
  call — and what the boundary needs is the objects, not the executable they
  would have gone into. Forcing the whole of `IO`'s surface produces a program
  that will not link, on `Crystal::EventLoop::Polling` internals a demand-driven
  build never reaches, and the units are written after the link. `IO`'s artifact
  fills now — 18 units, 14.8 MB — where it had been empty.

- **Measured what the library would be worth as an artifact** (SPEC.md Part V
  item 12e). A generated module the shape of a library — 103,002 lines, 5,000
  exported methods, declarations at the 5% of the source that Crystal's own
  library has them at — reads back from its `.iyimod` in 0.11 s against 0.43 s
  from source, in 25 MB against 163 MB. The daemon, on the same term, is 0.47 s
  to 0.33 s and costs 200 MB rather than saving it.

  `crystal tool bind` already writes a `.iyimod` for a Crystal namespace:
  `JSON` crosses 90.3% of its public surface unaided, `YAML` 78.0%, `URI`
  58.1%. What the rest waits on is the core types — `String`, `Array`, `IO` —
  which are not a namespace and so have no root to point the tool at.

- **The ecosystem and R-1, together: `--crystal` and `.iyimod` now work in one
  build.** A module that requires `json` compiles once into an artifact, and a
  program that requires Kemal links against it without opening its source. The
  two features were each half of the thing anybody actually wants.

  Three things had to be answered, and they were the same question three times
  — *a name in the module's object code that only the consuming program can
  define*, which is the rule `TypeIds` was already in the format for.

  - The main module's helpers, `~match<IO+>` first. The consumer emits them
    with its own numbering rather than the artifact carrying them, because a
    match against a virtual type compares against a range of type ids and those
    numbers belong to the program. A carried copy would have compared the
    consumer's ids against the producer's range and answered wrongly with
    nothing to see.
  - The module's requires. A module that required `uri` and a consumer that did
    not left `URI::Error.class:type_id` undefined at link time. They travel now
    — the new `Requires` section, format v20 — and the consumer replays them.
  - The `!dbg` location, fixed below.

  There is one copy of the library in the result, which was measured rather
  than assumed: `STDOUT` and `PROGRAM_NAME` are the same object on both sides
  of the boundary, and the specs assert it.

  What it saves is small and is written down as such: on a twelve-module app
  the modules cost 0.16 s from source and nothing from artifacts, against
  3.1 s for Crystal's library, which every build still reads from source.

- **`iyi daemon`.** A single-threaded `iyi-daemon` is built and shipped beside
  `iyi`; `iyi daemon start` holds Crystal's library analysed between builds. It
  takes about 0.3 s off the front end of a `--crystal` build — 0.81 s to 0.47 s
  on a twelve-module app — and costs about 200 MB resident per prelude it holds.

  Name your shard in a `--prelude` file of your own and it is held too, which is
  the largest effect by some way: 1.28 s to 0.60 s on the same app with Kemal.
  What the daemon is good at is holding the program's *dependencies*, not the
  library underneath them.

  Not offered before because iyi's own prelude takes 0.03 s to analyse and
  there was nothing to hold. `--crystal` gave it something.

- **A `.iyimod` records which library it was built against**, and importing
  across the two is refused by name in both directions. This replaces the old
  refusal, which was blunter and aimed at the wrong thing: `--emit-iyimod` and
  `--use-iyimod` no longer need iyi's own prelude. What they need is for the
  module and the program to agree on which library they mean. Both worlds are
  compiled by the same compiler and mangle the same names, so a mixed program
  would link — on the names that happen to agree.

- **`samples/iyi/calc`: a language, in the language.** Three modules — a
  scanner, a parser and an evaluator — reading a program from standard input,
  written against iyi's own 2,404-line library and nothing else. Every other
  sample is a page long, and a language that has only been used for pages has
  not been used.

  It grew the prelude by exactly what it asked for, which is the rule the
  prelude grows by: `String#[]`, `String#[](start, count)`, `String#to_i` and
  `read_input`. Nothing else was missing. `/` was not added, and that is the
  interesting one: iyi has no floats, Crystal's `/` on integers returns a
  `Float64`, and a name that means two things is what III.1.7a settled against
  — so integer division stays `//` in both.

- **Files can be removed.** `File.delete` uses `unlinkat` on Linux,
  `unlink` on Darwin and `DeleteFileA` on Windows. wasm32-wasi refuses it:
  deleting a path needs a preopened directory capability the prelude does not
  have. `samples/iyi/files.iyi` now deletes what it creates.

- **`derive` runs once, where the type is declared.** `derive <macro>` in a
  class or struct body resolves through the exported macro table, expands while
  the declaring type is processed, and the methods it generates belong to that
  module and travel in its artifact. `samples/iyi/derive.iyi` is built from its
  artifacts with `std/derives` deleted every build, so a consumer never runs
  the macro. The macro is handed the declaration's name and fields, built for
  the purpose: passing the declaration itself put the `derive` node inside its
  own macro argument, and no build that touched an artifact terminated.

- **A derive can ask what a field's type implements.** Each field carries the
  type it was written as, so `field[:type] <= ToJSON` is answerable — including
  where the type, the trait and the impl all belong to another module and arrive
  from its artifact, which is the `Order` case SPEC.md II.4 designs. The type is
  read from the annotation, because an instance variable's type is settled by a
  later pass and there is nothing to ask yet when a derive runs; R-2 is what
  makes that enough.

  A derive reads the declarations above it, so `getter n : Int32` is a field.
  One written below is refused, naming the call and which way to move it, rather
  than generating a method over the fields it happened to see. And because
  handing over a type hands over every question a macro may ask a type,
  `all_subclasses`, `subclasses` and `includers` raise inside a derive: they
  answer with the whole program rather than with a declaration, which is the
  caching promise R-5 rests on. Outside a derive they are untouched.

- **`derive named, counted` runs both.** Each macro named on one derive line
  runs in turn, left to right, reading the same declaration. A name nothing
  exports is reported at that name rather than at the line.

- **A Windows binary links, and then does something different every run.**
  Windows was one of the seven targets whose emitted objects CI audits and one
  of the six that had never been run. Running it found the object is fine and
  everything after the linker is not.

  Getting it to start needed two things the object audit cannot see. An
  LLVM-emitted object carries no `/DEFAULTLIB` directives, which an
  MSVC-compiled one would, so nothing pulls in `kernel32` or a C runtime. And
  naming the libraries is not enough: the *static* CRT (`libcmt`) links just as
  cleanly and then exits `0xC0000005` before `main` runs, while the dynamic CRT
  (`msvcrt ucrt vcruntime`) starts correctly. That was found with a ladder of
  programs whose smallest rung is `module w1` — it faulted too, which ruled out
  the allocator, the write path and `ExitProcess` in one step.

  What it does at run time cannot be trusted, in three different ways. The same
  binary, twenty runs, nothing changed between them: it has printed the right
  answer, printed `ache\w` (a fragment of a path from elsewhere in memory) where
  the program prints `HELLO, IYI!`, printed `BEEP ` with the digits gone, and
  exited `0xC0000005`. The two wrong-output shapes are a case conversion and a
  number rendered into a string, which looked like a lead until a run
  access-violated: an intermittent AV on a four-line program is a wild write,
  not a formatting bug.

  The obvious theory is recorded as wrong so nobody spends the afternoon on it:
  `HeapAlloc` not clearing cannot be it on its own, because the POSIX path
  allocates atomically with plain `malloc`, which does not clear either, and
  macOS has never printed the wrong thing.

  So Windows is not a run target and the README does not say it is. CI keeps a
  twenty-run watch that always passes and prints the tally — right, wrong,
  crashed — because there is no property of running an iyi program there that
  currently holds twenty times out of twenty.

- **The Windows link command names the libraries it needs.** An LLVM-emitted
  object carries no `/DEFAULTLIB` directives the way an MSVC-compiled one does,
  so `--cross-compile` printed a `cl.exe` command that could not link the object
  it had just produced: seven unresolved externals, six of them `kernel32`. The
  prelude's Win32 blocks now carry `@[Link("kernel32")]` and the dynamic CRT,
  and CI links with the printed command rather than one written into the
  workflow, so the command a person is told to type is the command that is
  tested.

- **An iyi program is run on wasm32-wasi every build.** The module imports four
  `wasi_snapshot_preview1` functions and nothing else, and it linked and then
  trapped on `unreachable` before printing anything. wasi-libc's entry stub does
  not call `main`: clang renames a C `main` to `__main_argc_argv`, the stub
  calls that name, and a module defining only `main` leaves the stub's weak
  reference unbound and traps the first time it is called through. The prelude
  now defines the name the stub calls, and `hello.iyi` runs under wasmtime with
  the same bytes it prints natively.

  And the command printed for this target is now `cc --target=wasm32-wasi`
  rather than `wasm-ld ... -lc`, which linked a module with no entry that no
  host could start. Only the driver knows where its sysroot keeps `crt1.o`, so
  naming the driver is the only way to print a command that produces a program.
  CI runs that printed command with wasi-sdk's clang as the `cc` it names.

- **A Crystal namespace can be bound, built and called from an iyi program, in
  two commands.** `--emit-bind` on the keep file's own build puts the per-type
  units into the artifact, with the type ids and constants they refer to, using
  the collectors an iyi module's artifact has always used — and the consumer
  links what the artifact carries:

  ```
  crystal tool bind -e ABCGreeter --emit-bind mods shard.cr
  crystal build --iyi-keep ABCGreeter --emit-bind mods -o keepbin abc_greeter_keep.cr
  iyi build --crystal --use-iyimod mods -o app app.iyi
  ```

  No `nm` and no `objcopy`, where four printed steps had been and had never
  worked at the end. The object `--emit obj` makes is a whole program and
  carries Crystal's library with it; an ordinary build leaves one object per
  type and the ones a namespace owns carry no runtime at all.

  `--crystal` on the consumer is not decoration: the unit numbers
  `Pointer(LibUnwind::Exception)` whatever the shard does, because a `String#+`
  can raise. The artifact is marked `crystal_library: true` for the same reason,
  which it always was — it was written `false` on an argument about what a
  boundary stands between, and that argument does not survive looking at what
  the unit refers to.

  A constant crosses as the assignment that makes it, so the consumer builds it
  in its own program at the time III.5 says — which is what the unit needs,
  referring to `Store::TABLE` and defining nothing. `Store.word(1)` answers
  `one`, where the same call used to segfault on the first read. Its own
  constants only: a unit refers to Crystal's as well, and those belong to the
  library the consumer already has.

  What a boundary cannot carry is an enum, and `crystal tool bind` says so by
  name instead of calling it a namespace skipped whole. iyi has no `enum`, so
  nothing on the far side declares one: a signature naming an enum cannot cross
  and neither can a type holding one. It is what `JSON` waits on — it binds to
  19 units and 7.5 MB and then stops on `JSON::PullParser`'s `ObjectStackKind` —
  and it is a language feature rather than another thing about object files.

  One nested inside a type under the root crosses as well, written
  `Inner::X = ...` — which defines rather than reopens wherever the namespace
  exists, and the declarations rendered above it are what make it exist.

- **Lookaround, and the reason it was refused was wrong.** `Iyi::Rx` supports
  all four forms, `(?=)`, `(?!)`, `(?<=)` and `(?<!)`, nested to any depth. The
  engine's header and SPEC.md both said lookaround was the price of RE2's
  linear-time guarantee, on the premise that it needs a backtracker. It does
  not: a lookaround over a regular inner pattern is a regular property of a
  position, answered by a pre-pass costing one state set per character and
  nothing per position. RE2 omits it because of its one-pass DFA design, not
  because linear time forbids it. The guarantee is unchanged, and what it
  actually costs is the constructs that are not regular, backreferences,
  recursion, subroutine calls and conditionals. Lookbehind here is not
  length-limited the way pcre2's is, so it accepts patterns pcre2 rejects.
  SPEC.md III.10 and Appendix B #17 carry the correction with the earlier
  reading still in them.

  **A capturing group inside an assertion is refused, and that refusal is
  new.** The pre-pass answers whether an assertion holds at a position and
  never which text its inner pattern consumed, so the group cannot be set.
  Reporting an empty capture where pcre2 reports a real one is the quiet
  difference this engine exists to avoid, so it refuses at compile time with
  the position instead.

- **The escapes and the folding a pattern in this tree actually reaches for.**
  Named groups in all three spellings, `(?<name>)`, `(?'name')` and
  `(?P<name>)`, numbered alongside unnamed ones the way pcre2 numbers them,
  with name lookup on the match. `\p{...}` and `\P{...}` for L, Lu, Ll, N and
  M, braced or single-letter, inside a character class or out, with every other
  category refused by name rather than approximated. `\v` as pcre2's vertical
  whitespace class and `\V` as its complement. `\x{...}` at any digit count,
  refusing at the offending position for no digits, a missing brace, a value
  above U+10FFFF, or a surrogate, which pcre2 in UTF mode refuses too. And
  `(?i)` folds past ASCII now, through
  `Char#downcase(Unicode::CaseOptions::Fold)`, simple case folding, the same
  relation pcre2 uses.

  `spec/compiler/iyi/rx_spec.cr` holds all of it against pcre2 over one corpus,
  31 examples including exhaustive codepoint sweeps for the character classes.
  None of it cost a library: `bench/dependency_floor.sh` still exits 0.

  Three readings stay this engine's own, each narrow and each stated rather
  than left to be discovered. `\d` is any Unicode number where pcre2 under
  `UCP` means `\p{Nd}` exactly, because no public stdlib predicate answers Nd
  alone, which is also why `\p{Nd}` is refused rather than approximated. `ß`
  and `ẞ` do not match caselessly here, because `ẞ` full-folds to `"ss"` and
  chasing that one pair opens others, simple lowercase not being symmetric.
  And lookbehind follows the union law here where pcre2 does not: on `"a"` at
  byte 0, `(?<=(?:a|$))` searched from 0 reports byte 0, the same pattern
  anchored at 0 reports nothing, and the ungrouped `(?<=a|$)` is right, so the
  trigger is the wrapping group rather than the branch lengths.

### Fixed

- **A boundary whose root is a module was read as carrying nothing.**
  `bound_names` asks whether the program has a type by each name an artifact
  declares, and asked it bare. That is right when the root is a *class* —
  `-e ExceptionPage` declares `ExceptionPage` and the program has one — and
  wrong when the root is a *module*: `-e Radix` declares `Node`, `Tree` and
  `Result` at the artifact's own top level, and the program has no top-level
  `Node`. It has `Radix::Node`.

  So `radix.iyimod` read as **6 types, 0 this program can name** while sitting
  in the same directory as a `Kemal` that names `Radix::Tree` eight times, and
  every one of those signatures went on waiting for a boundary that was already
  carrying the type. Asked under the artifact's root as well, and recorded
  under it too because that is how the producer writes them.

  Measured on the real shard: **`Kemal` goes from 168 signatures and 12 waiting
  to 182 and 0.** Nothing it names is undeclared any more.

- **A method that takes a block is now called with one, and rule 1's residual
  reaches zero.** `infer_return` instantiates a method on purpose to read what
  it answers, and it did that with no block — so `JSON::Builder#string`, which
  has an overload taking a value and one taking a block, matched the first and
  answered `wrong number of arguments (given 0, expected 1)`. Its return type
  was then the last thing on the boundary standing on the shard's word, over a
  block the annotation had already described in full.

  Two pieces. The call gets a `Block` of the annotated shape — the same block
  the keep file has written as text since blocks first crossed, `{ |b0| nil }`
  or an `uninitialized` of the output where the output is not `Nil`. And it
  gets a `parent_visitor`, because a block's body is code and code is visited;
  a blockless call never needed one, and the compiler says so exactly:
  `Iyi::Call#parent_visitor cannot be nil`.

  **Crossing on a return nobody checked: URI 0 of 55, JSON 0 of 181, YAML 0 of
  194.** Blocks being instantiable moves the other half too — 64 return types
  read in `JSON` where the tool had refused, 81 in `YAML`.

  One of the two this closed was not the tool's fault and is worth saying so:
  `YAML::Any#to_json_object_key` names `JSON::Error` in its body, and the probe
  it was measured with required only `yaml`. The tool refused correctly and the
  input was short. `YAML` reads 194 signatures with both required, against 193
  with one.

- **A block-taking method crossed a bound boundary and could not link.**
  IV.1g settles what such a method does: its machine code is the caller's, so
  the producer emits each instantiation private to the unit that called it and
  no symbol for one leaves the artifact — and its body travels in `MonoBodies`
  instead, for the consumer to compile its own from the block it wrote. That
  paragraph says explicitly that the question is about a `def` and not about a
  type.

  `crystal tool bind` was answering it about a type. Only a *generic* type's
  methods carried their bodies, so an ordinary class's block-taking method
  crossed as a declaration with nothing behind it — a promise nothing could
  keep, and `undefined symbol: *Shard::Part#each<&Proc(Int32, Nil)>` at the end
  of a build with no other complaint.

  It carries the body wherever the method is written now. Both shapes round
  trip and both are in `bench/bind_roundtrip.sh`: one that `yield`s and one
  that captures its block as a `Proc`. The first guess was that only the
  yielding one broke, because `yield` is inlined; a captured block fails
  identically, so the rule is the block. The surface does not move — `JSON`
  180 signatures, `YAML` 193, `URI` 55, before and after.

- **What is left of III.6 rule 1 is counted where it is owed, and it is two
  methods rather than eighty.** The report counted every written return that
  could not be held against an answer: URI 27, JSON 13, YAML 39. Most of those
  methods do not cross at all — a parameter with no type, a block nobody
  annotated, a splat — and are already refused by name further down, so
  counting them as unchecked said the boundary was trusting things it had never
  carried.

  Counted over the signatures that actually travel: **URI 0 of 55, JSON 1 of
  180, YAML 1 of 193**, and the report names them with the whole reason rather
  than a reason cut to a column. `JSON::Builder#string` — the tool builds no
  block for the call it synthesises — and `YAML::Any#to_json_object_key`.

  An abstract def is not among them any more either. It has no body to
  instantiate and no symbol of its own: what a caller reaches is an
  implementation, and every implementation is an ordinary method this tool
  checks as itself. `YAML::Nodes::Node#kind` was being counted as a return
  standing on the shard's word when it is one carried by the methods
  underneath it.

- **`bench/bind_speed.py` said a shard reaching into another one cannot be
  bound, and that stopped being true two commits before anybody reread it.**
  The header gave `Kemal` numbering `Array(Radix::Node(...))` as the case and
  a generic travelling as bodies rather than declarations as the reason. Both
  halves have since been answered — a generic carries its declaration *and* its
  bodies, and the build that fills a boundary reads the boundaries beside it and
  adds the import edge — and the paragraph went on asserting the old state.

  Corrected by measuring rather than by reasoning, and without the network: a
  two-shard tree of exactly that shape — a generic `Node(T)` in one, a second
  whose object code numbers `Array(Node(String))` and whose declarations name
  no `Node` — binds, links, runs, and prints what the source arm prints. The
  order matters and the header now says so: the reached-into shard is bound
  first and named with `--use-iyimod`, because only a build that sees that
  boundary can add the edge. Without it the consumer stops at import with
  `"kemal" numbers Array(Radix::Node(String)), and this build cannot name it`.

  SPEC.md III.6 already recorded the correction and needed nothing; it also
  names what real `Kemal` still waits on, which is three types belonging to
  other shards. The stale sentence carried a stale number besides — it called
  the smallest sweep 1,627 lines where the bench prints 2,167.

- **`crystal tool bind` holds a written return type against what a caller is
  actually handed, and the two are not always the same.** III.6 rule 1 says the
  binding asserts and is not checked. Half of it already was: a method whose
  return type nobody wrote is instantiated on purpose and the answer read. The
  other half — a method that *writes* its return type — was copied out verbatim
  and held against nothing, on the premise that what Crystal was told is what
  Crystal does.

  It is not. Crystal narrows a return restriction to what the body produced, so
  `def wider : String?` returning a `String` types its call **`String`**, and a
  consumer told `String?` holds a union where the object code answers a bare
  pointer. That is rule 1's "a call that returns something of another type",
  reached without anybody writing a wrong signature.

  Five in Crystal's own library, and each is a different shape: `JSON::Any#size`
  and `YAML::Any#size` say `Int`, which is a family head and not a type anything
  can hold; `JSON::Lexer.new` says the abstract base where the factory hands
  back `StringBased` and `IOBased`; `YAML::Schema::Core.parse_scalar` declares a
  union carrying `Slice(UInt8)`, which it never produces. The report names them
  and counts what is left: URI **40 agree, 0 disagree, 27 could not be checked**,
  JSON 119/3/13, YAML 111/2/40. Where the two disagree the artifact carries the
  **answer**, because the symbol is named after the answer and not after the
  restriction — see the round trip below, which is what settled that.

  **The first version of this check read the method's body rather than its call,
  and it was wrong in the direction that matters.** `def discards(io : IO) : Nil`
  has a body producing an `IO` and a caller receiving `Nil`, because `: Nil`
  discards; reading the body reported three defects in `URI` alone that were not
  there. The question a boundary asks is what a *caller* is handed, and the spec
  now pins the `: Nil` case for that reason.

- **A return type is asked whether a variable could hold it, which only the
  parameters were being asked.** `Int` is the head of a family on either side of
  the arrow: a method answering one has a symbol per member exactly as a method
  taking one does, and the generated keep file cannot compile either. `storable`
  looked at the arguments alone, so `JSON::Any#size : Int` was counted as a
  signature that crosses. JSON goes **181 → 180** and YAML **194 → 193**; URI is
  unchanged at 55.

- **`bench/build_speed.py` has not built anything since the identity cutover,
  and it is the gate for the one claim this project is built around.** It asks
  a wrapper where this checkout's sources are, and `f55ba16cb` renamed the
  variables it asks for to `IYI_*` while leaving it asking `bin/crystal`. The
  two command surfaces answer in their own vocabularies by design, so
  `crystal env IYI_PATH` is not an error — it prints an empty line and exits 0.

  The bench checked the exit status, got 0, and passed the compiler an
  environment with no search path in it at all. Every build then failed with
  `can't find file 'iyi/prelude'` and every row of the table printed a dash.
  It does exit non-zero, so it was never *silently* wrong; it was simply not
  being run.

  Two changes, and the second is the one that matters. It asks `bin/iyi`, which
  is the surface that knows those names. And it checks the **answer** rather
  than the status, because an exit code cannot see an empty string — a bench
  that cannot find the path now says which one it wanted.

- **`bench/incremental.py` was broken the same way, and it is the harness
  behind the number on the front page of the README.** Same shape exactly: it
  asked `bin/crystal` for `IYI_PATH`, got an empty line and a 0, and every
  build in it failed with `can't find file 'iyi/prelude'`. Fixed the same way,
  and it exits non-zero too, so this was also not being run rather than being
  believed.

  Running: 30 modules, 300 types, 7,208 lines, editing one module's body —
  **iyi 0.07 s, `go build` 0.09 s, Crystal 0.76 s** on a release compiler. The
  same edit with no artifacts is 0.18 s, so R-1 is worth 0.11 s of it.

  Worth putting beside the other bench rather than apart from it. `medium.iyi`
  is 6,900 lines in **one file** — no modules, no artifacts, nothing to cache —
  and there iyi is 0.13 s against Go's 0.02 s. iyi loses on a monolith and wins
  on a project, and SPEC.md's 0.1.0 section said only the first half because
  only the first bench could run.

- **The same bench withheld iyi's own figures at scale whenever Go was
  absent.** The 300-type pair is timed only after both halves are built and run
  against each other, which is right for the comparison and wrong for
  everything else: on a machine with no Go the whole block was dropped, and
  that block is the size SPEC.md's scale question is about. "The pair disagreed"
  and "there is no Go here" are now different answers. The first still drops the
  rows; the second prints iyi's and marks the Go column as not measured.

  With them back: at 6,912 lines, front end 0.05 s, end to end 0.39 s cold and
  **0.13 s warm** on a release compiler.

- **`gsub` copied the tail twice on an empty match at the end of the subject.**
  `Iyi::Rx.gsub("abc", /$/, "<>")` answered `"abc<>abc"`. An empty match at the
  very end left the cursor behind it, so the text between the cursor and the
  end was appended a second time with the tail. `/$/` over `"abc"` is the
  smallest case and reaches it with no lookaround in sight, so this was already
  wrong before any of the above.

- **`crystal tool bind` says why a bound shard cannot be linked into a program
  that has Crystal's runtime either.** A consumer built with `--crystal` is the
  program that *has* the runtime the shard's initialisation was missing, so it
  ought to be the answer; instead the link fails on `Crystal::Hasher::seed`,
  `Thread::threads`, `Fiber::fibers` and every other runtime global, defined
  once by each side. The object this pipeline makes is a whole program — a keep
  file is compiled like one — so it carries the library with it, and a program
  can have that library once. Without it the shard's state never starts; with
  it, nothing links. The names were not the problem and neither were the
  constants: the packaging was.

- **A harness for what the daemon takes off a whole build**
  (`bench/daemon_full_build.py`), which SPEC.md IV.1d had said was too noisy to
  publish. Twelve modules under `--crystal` with codegen and a link, eight
  alternating pairs, a module edited before every build, and it refuses to run
  on an unoptimised binary — the three corrections IV.1d had to make, built in
  so they cannot be forgotten again. **0.63 s to 0.46 s, or 26%**, with two runs
  agreeing to a hundredth.

  What was called noise was largely the measurement: `/usr/bin/time`, whose
  negative elapsed times IV.1d records, is not installed on this machine. The
  app here is lighter than the one the published table was made from — its
  front end is 0.35 s against 0.81 s — so this is a new row rather than that
  row measured further.

- **The prelude cache key is checked by the compiler now, not by whoever
  remembers.** A cache key is a claim that everything not in it does not matter,
  and this one was written when the only thing reading it was prelude analysis;
  every switch added since had to be checked against it by hand, silently.
  `--use-iyimod` is what happened when somebody did not — accepted, ignored, and
  the build compiled every module from source without a word. Each of
  `Compiler`'s switches is now written down as one of three things: in the key,
  re-applied when a build adopts a preanalysed prelude, or reaching neither.
  Adding a property fails the build until it is given one of them.

  Two of the classifications are judgements rather than facts, and saying so is
  the point: `mcpu`, `mattr` and `mcmodel` reach codegen and not analysis, and
  `progress_tracker` and `stderr` are where output goes — `new_program` sets the
  first and the adopt path sets neither.

- **`crystal tool bind` asked a hand-written list what an iyi program can name,
  and the list was wrong in both directions.** It claimed `Void`, `UInt32` and
  `Float64` — which iyi's prelude never declares — and left out `Slice`, `Int`,
  `Tuple` and `NamedTuple`, which `Program#initialize` creates for every program
  before any prelude is read. Those four were most of what the boundary appeared
  to be waiting on, so the list invented the work it was being read to size.

  `Program#builtin_type_names` records those types where they are made, and the
  tool asks it. `JSON` crosses 152 → 168 signatures, `YAML` 158 → 166, `IO`
  157 → 270 with what it waits on falling 140 → 5. The percentages do not move
  and nothing that crossed stopped crossing. What is left of "the core" is `IO`
  — nearly done itself — and then `Time`, `Time::Span`, `Set`, `File::Info`.
  See SPEC.md Part V item 12e.

- **CI could not package the tarball, and the guard that stopped it was right.**
  `iyi-tarball` carries `release := 1` and make applies that to what it builds
  for that goal — so the workflow naming `iyi` first built an ordinary one, and
  the tarball found it up to date by file times and refused. That refusal is
  exactly what `check_iyi_is_release` was added for; what was missing was the
  workflow catching up with it. It asks for `iyi-tarball` alone now.

- **The four steps `crystal tool bind` prints are taken by a spec now**
  (`spec/compiler-cli/bind-pipeline_spec.cr`): bind a shard, compile its keep
  file to an object, read the symbols, globalise them, and build an iyi program
  that links against it — then run the program and read what it printed. Three
  of the four steps were wrong when they were first run by hand, and each was
  invisible until something later failed, the later thing being `ld`. It skips
  itself where binutils is missing, or where `crystal` and `iyi` were built from
  different commits, since an artifact is read only by the build that wrote it.

- **`crystal tool bind` says that a bound shard's run-time state does not
  cross.** Crystal runs a constant's initialiser from `__crystal_main` and
  compiles the reads unguarded; a consumer has its own `__crystal_main` and
  never calls the shard's, so the constant stays null and the first read
  segfaults. A folded constant is fine — `LIMIT = 10` reads 10 — and one built
  at run time is not.

  Calling the shard's `__crystal_main` does not fix it, which was tried:
  renamed out of the way with `objcopy --redefine-sym` and called from the
  consumer, it segfaults *inside* the initialisation, before reaching any
  constant. Crystal's top level expects Crystal's runtime — a thread, an event
  loop, the exception machinery — and an iyi program is not one. So a boundary
  carries code that needs no initialisation, and that is the bound on it today.

  An earlier draft of this entry said the failure was silent — "no error at any
  step, the program answers wrongly". That was a measurement mistake: the exit
  status being read was a `printf`'s rather than the program's. It segfaults.

- **A method has as many symbols as it has ways of being called, and the keep
  file named one.** The mangled name carries the types at the *call site*, not
  the types in the declaration: `JSON.parse(input : String | IO)` is one
  declaration and three symbols, and the file named only the one where the
  argument is the declared union. Every consumer that passed a plain string
  linked against nothing. It emits the product of the parameters' shapes now,
  which measures smaller than it sounds — a union parameter is about one in
  twenty, 7 of `IO`'s 103 and 1 of `JSON`'s 53 — with a cap that reports itself
  rather than expanding without limit.

- **A `def self.` module function crossed under the wrong symbol.** A module
  written `extend self` puts its functions on the module and mangles
  `*Widget@Widget::polite<String>:String`; one written `def self.polite` puts
  them on the metaclass, which has no `@`. Both were recorded as the first, so
  every `def self.` in a shard produced a declaration the consumer called by a
  name nothing emitted — and Crystal's own library is written the second way
  throughout. The receiver is recorded now, which the artifact's format already
  had a field for and the type path already used.

- **A bound shard's module path is `camelcase` run backwards, and using
  `String#underscore` for it broke every acronym.** `underscore` answers `json`
  for `JSON`, and `json` camelcases back to `Json` — so the producer emitted
  `*JSON@JSON::...` while the consumer asked for `*Json@Json::...`, and `ld` was
  the only thing that ever said so. `camelcase` starts a group at every
  upper-case letter, so the inverse of `JSON` is `j_s_o_n`, which is a legal iyi
  path and comes back whole; `HTTPServer` is `h_t_t_p_server`, which
  `underscore` had flattened to `http_server` and lost. A shard named `ABC`
  links and runs.

  This corrects what the previous release notes said. They claimed `JSON`,
  `YAML`, `URI` and `HTTP` were outside the mapping's image and that the
  library-as-artifact thesis waited on a question about iyi's module paths.
  There was no such question: the mistake was reasoning about `underscore`'s
  image rather than `camelcase`'s.

- **`crystal tool bind` says when a root's name cannot survive the trip.** What
  actually falls outside is a name the grammar cannot spell — `Foo_Bar` needs
  two underscores running and `camelcase` reads two as one, so it comes back
  `FooBar`. Both sides mangle alike, so such a root produces an object file
  whose symbols no consumer will ever ask for, and `ld` is four steps too late
  to hear it.

- **A bound shard's iyi module name was the root downcased, and the symbol is
  what that broke.** Both sides mangle alike, so `Greeter.polite` is
  `*Greeter@Greeter::polite<String>:String` compiled from either language — but
  only if the consumer's module *is* `Greeter`, and a consumer builds that name
  by camelcasing the path it imported. `MyGreeter` became `mygreeter` became
  `Mygreeter`, which mangles to a symbol the shard's object file does not
  contain, and nothing said so until the linker did. The name is `underscore`d
  now, which is what `camelcase` inverts, with `::` as `/`.

  With it, a program built from a bound shard links and runs — the first time
  the four steps this tool prints have been taken end to end.

- **The pipeline `crystal tool bind` prints did not run.** A mangled name
  carries the types it was compiled for and a union prints with spaces in it —
  `*JSON::Any#as_a?:(Array(JSON::Any) | Nil)` — so the unquoted `$(...)` in the
  `objcopy` line split 50 of `JSON`'s 301 symbols into fragments and objcopy
  answered with its usage. It is an `xargs -0` now, and the four lines run as
  printed.

- **A boundary can now name another boundary's type, which is what `IO` was
  for.** `JSON`, `YAML` and `URI` all take an `IO`, so binding them is worth
  nothing unless the artifact can say so. The producer calls the type `IO`; a
  consumer that imported it calls it `Io::IO`, and an artifact that wrote the
  first resolved to nothing. Names from the boundaries passed in `--use-iyimod`
  are written the way the consumer will see them, and the modules they came from
  travel as the artifact's `imports`, so `import json` alone is enough — the
  consumer does not have to work out that it needs `import io` as well.

- **A field's type crossed as `IO+`.** That is how a virtual type prints — a
  fact about this build's dispatch rather than a name anybody can write — and a
  field declared `IO+` is one no consumer can read back. `infer_return` had
  devirtualised its answers since it was written; the field walk never did.

- **A bound namespace's artifact named types the consumer could not resolve, and
  nothing had ever tried to read one back.** The tool had no spec at all: every
  check it carried was a number it printed, and a number cannot say whether
  anything can consume the artifact printed beside it. `spec/compiler/bind_spec.cr`
  is that check, and it failed the first time it ran.

  An artifact's module name is the root downcased, and a consumer builds a type
  back out of it by camelcasing — a mapping iyi keeps reversible on purpose
  (SPEC.md IV.6 #6), so `MyLib` returns as `Mylib` and `JSON` is not in its image
  at all. Meanwhile the declarations inside still said `MyLib::Entry`. A class
  root never showed it, because its own name is a declaration in the file and
  `MySink::Entry` resolves against that wherever the module lands. The producer's
  prefix comes off a module root's declarations now, which is the same property
  said directly: what an artifact declares belongs to the artifact.

- **`crystal tool bind` exported methods that take a block nobody annotated.**
  A block-taking method is compiled per block *type*, so one whose block has no
  written type has no single symbol to declare. `infer_return` refused these
  already — but only when it ran, and a method that writes its own return type
  never reaches it. No count showed it; `Time`'s generated keep file did, by
  refusing to compile with *`Time.measure` is expected to be invoked with a
  block*. They are refused and reported on their own line now.

- **`crystal tool bind` can be pointed at the boundaries already written.**
  `--use-iyimod DIR` — the same switch a build uses — reads the `.iyimod` files
  there, and a signature naming one of their types is no longer waiting on
  anybody. Each name is checked against the program rather than trusted, since a
  class root's declarations are absolute and a module root's are relative to a
  name the file does not record; what is dropped is counted and printed.

  It is what closes the question item 12e opened. With `IO`, `Time` and
  `SemanticVersion` bound, `JSON` crosses 168 → 181 signatures, `YAML`
  166 → 192 and `URI` 48 → 55 — the exact gains the unlock report predicts, and
  it predicts them by a different route, which is the two checking each other.

  The counts also stopped calling a free variable a type. `T`, `self` and a
  block returning `_` are not types anybody can declare, and counting them
  beside `IO` said there was more waiting than there was; they have their own
  line now. What is left: `JSON` and `URI` wait on **nothing** anybody could
  declare, and `YAML` waits on `Set` alone — which is generic, so it travels as
  bodies rather than declarations and belongs to a different piece of work.

- **`crystal tool bind`'s keep file never descended into nested types.** A
  nested type travelled as a declaration while its methods were named by
  nobody, so the artifact promised symbols the object file did not carry — a
  link error rather than a compile one, and invisible until something linked.
  `JSON`'s artifact holds 16 types and the keep file reached 9 of them, leaving
  16 methods on the other 7 unemitted. The walk recurses now, and the counts
  printed beside the artifact are counted through the nesting too, having read
  as top-level-only for the same reason.

- **`crystal tool bind` generated a keep file that could not compile when
  pointed at a core type.** A shard's root is a module — `Kemal`, `JSON` — and
  the tool assumed one everywhere: it reopened the root as `module IO`, which is
  a class, and called `IO.write`, which is an instance method. A class root's
  own surface and its constants now stay behind and are reported by name and
  count, rather than being declared with no symbol to link against. What travels
  is the types under it, which is enough to make `crystal tool bind -e IO`
  produce an artifact and an object file end to end.

  It carries the root itself now. A module's own methods are module functions
  and a class's are its type's, so a class root travels as one declaration
  holding everything under it — `IO` with `IO::Memory` and twelve more inside:
  14 types, 148 methods, 311 symbols. Its constants still stay behind.

- **`crystal tool bind` declared private types.** `IO::Encoder` is private, and
  an artifact naming it names a constant the consumer is not allowed to write.
  Method visibility was already checked; the type's was not. The generated keep
  file is what found it, being the first thing outside the shard to say the name
  out loud.

- **`crystal tool bind` counted a signature as crossing when a variable could
  not hold its parameters.** A name being writable is not the same as a value
  being holdable: `Int` is the head of a family, and a method taking one is
  compiled once per member with a symbol apiece, so there is no single symbol
  to declare. `can_be_stored?` is the compiler's own answer and the tool asks
  it now, reporting those signatures on their own line rather than as types
  nobody has declared. It is what the counts above are corrected by — they
  read 182, 168 and 286 before it.

- **`crystal tool bind` read restrictions as text, and it flattered the core.**
  A method inside `JSON::Token` writes `kind : Kind`, which is
  `JSON::Token::Kind` — the shard's own type, already travelling — and the tool
  counted it as a type nobody had declared. `self` went the same way: a method
  returning `self` in `URI` returns `URI` and waits for nobody. Every such
  spelling pushed the "what this boundary is waiting on" list in one direction,
  *towards the core*, which is the claim that list was being used to support.

  Restrictions are resolved against the owning type now. The boundary the tool
  can already write grows by 33 signatures — `JSON` 142 → 152, `YAML` 142 → 158,
  `URI` 41 → 48 — and the percentages of surface needing no human do not move,
  because those measure a different thing and resolution does not touch it. Two
  `YAML` signatures returning a bare `Array` stopped crossing, which is a
  correction rather than a loss: a declaration that says `Array` without saying
  of what is not one a consumer can use.

  With the list true, `IO` is first for all three namespaces and by more than
  before — +13, +21, +8 — against 21 for everything generic. See SPEC.md Part V
  item 12e.

- **The tarball could be built from an unoptimised compiler, and was.** `build:`
  sets `release := 1`; `iyi-tarball` did not, and even asking would not have
  been enough — make rebuilds on file times, so a `.build/iyi` left over from an
  ordinary `make iyi` is newer than every source and gets packaged as it is.
  Nothing about the tarball would look wrong; every build every user ran would
  simply go through an unoptimised compiler. The target now asks the binary
  rather than the build: `--version` says which it is, and packaging refuses
  otherwise.

  This is also why the daemon numbers first published here were about three
  times too generous — they were measured with one of those binaries. See
  SPEC.md IV.1d for the corrected table and for the other two ways the
  measurement was wrong.

- **The tarball could not build a program that requires Kemal.** `install_iyi`
  cut `compiler/` from the copy of Crystal's library it ships, and the standard
  library requires it: `crystal/syntax_highlighter` requires
  `compiler/crystal/syntax`, the exception page requires the highlighter, and
  Kemal requires the exception page. README's headline example did not work in
  the thing people download, and 0.2.0 shipped that way. CI now builds a shard
  out of the unpacked tarball.

- **The build daemon died after serving one build from another directory**, and
  could not find `lib` in the client's project. Three bugs, all older than this
  release and all the same fact forgotten — the daemon runs in its own
  directory and the client does not. The third was that `CrystalPath` is a
  struct, so fixing the second through a getter mutated a copy and changed
  nothing. Every existing daemon spec passed through all three, because each
  passes an absolute path and starts the daemon where the runner is.

- **A build that adopted a preanalysed prelude ignored `--use-iyimod`.** That
  path never runs `new_program`, so a build's switches were whoever analysed
  the prelude's — none. The flags, the target and the prelude are in the
  analysis's cache key and so are safe; `--use-iyimod` is not, and was accepted
  and silently ignored while every module was compiled from source.

- **A constant an artifact reads carries a location.** The reads a consumer
  performs on an artifact's behalf were synthesised without one, and LLVM
  refuses a call with no location inside a function that has debug info. It
  never fired under iyi's own library and fired at once under Crystal's, which
  is where it was found — while looking at whether artifacts and `--crystal`
  can be used together. They now can; this was the first of the three things in
  the way.

### Changed

- **A module path is read from the root, not from where it is written.** A
  module called `samples/calc` importing `calc/lexer` resolved `Calc` to
  itself, then said the module was not imported: a true-looking sentence about
  the wrong thing. A module's path is its file's path (R-1), so it cannot mean
  something different depending on where it appears. Found by writing the
  sample above, which is called `calc`.

- **`Array#sort` is `sort_in_place`, and `sorted` is the copy.** A plain `sort`
  meant the opposite thing in the two libraries — it sorted the array under
  iyi's and returned a copy under Crystal's — with no error either way, which
  is the worst shape a difference can take. The plain verb is not in this
  library now, so the same call is an error under one and Crystal's meaning
  under the other.

  Measured before deciding: of everything iyi's library mutates — `<<`, `[]=`,
  `concat`, `shift`, `sort` — only `sort` disagreed, because Crystal writes `!`
  on the mutating member of a *pair* and plainly for the rest. One method
  today, and the shape every future pair would have had. SPEC.md III.1.7a has
  the three options that were on the table.

  The error teaches the rule: a missing name whose participle exists says so,
  which the suggestion machinery could not — `sort` to `sorted` is two edits.

- **iyi answers as iyi.** `iyi tool` printed `Usage: crystal tool`, and it was
  the shape of the bug rather than the string that mattered: the banner was a
  constant interpolating the program name, and a constant is built before the
  entrypoint has said which of the two binaries this is. `clear_cache --help`
  printed the literal text `#{Command.program_name}` at a user, because its
  heredoc was quoted. `repl --help` printed nothing at all. `iyi foo` could
  never find `iyi-foo`: the git-style subcommand lookup was hardcoded to
  `crystal-`, so the extension point existed for one binary of the two.

  Underneath, the compiler carries its own name: `Iyi` is the namespace,
  `src/compiler/iyi` the source, `IYI_*` its nineteen settings, `~/.cache/iyi`
  the cache, `IyiPath` the thing that reads `IYI_PATH`. `bench/identity_floor.py`
  is the gate, and the number it reports went from 12,426 lines across 178
  paths to zero; every remaining mention of Crystal is listed there with the
  reason it genuinely means the other language.

  Nothing about the compatibility binary changed, and that is asserted rather
  than assumed: `crystal` still answers as `crystal`, still reads `CRYSTAL_PATH`
  and its siblings, and `require "compiler/crystal/syntax"` still resolves.
  Crystal's own standard library does that, and anything that used the compiler
  as a library may too. Where both names are set for one setting, iyi's wins.

  Two of the defects were only visible on Linux CI, and both were the same
  mistake: a local run that set `IYI_PATH` by hand, and a gate whose
  `git ls-files` exited 128 inside a container and so checked nothing.

Master is `0.3.0-dev`. Under the artifact rule 0.2.0 introduced, that means
every build of it interoperates with nothing but itself: a version between two
releases names no compiler, so it cannot be handed one released artifact and
told they match.

## 0.2.0 — 2026-08-20

**A program chooses its library.** 0.1.0 had iyi's own 1,184-line prelude, and
that was most of what stood between the language and anybody's real program.
It turned out not to be a library problem: a prelude is a library and the rules
are the language, so a program can keep one and change the other. `--crystal`
does, and there `require` means what it means in Crystal. Nine shards were
swept through it and a Kemal server written in iyi serves HTTP; how many of the
rest work is not something this release measured.

Two more entries take the rules further out — `pub` reaches a macro and a
constant — and closing each found the same hole underneath: a surface nobody
wrote and nobody could refuse.

Artifacts written by this release are read by every other build of it, on the
same target and under the same flags. A `-dev` version between two releases
names no compiler and interoperates with nothing but itself, which is the rule
below doing its job rather than an exception to it.

### Changed

- **The tarball carries Crystal's library, so `--crystal` works in what people
  download.** It shipped iyi's own 56 KB and nothing else, so the release's
  headline feature answered `require "json"` with "can't find file" outside a
  checkout. It ships both now — 13.4 MB to 14.9 MB — and CI runs a `--crystal`
  program out of the unpacked tarball, which is where this was found and where
  it would have been found again.

- **`make cli_spec` says once when the daemon and the compiler are different
  builds.** The daemon refuses a client built from another compiler, correctly
  — it holds an analysed prelude — but the spec saw that as nine failures, each
  printing two version strings, with the reason in none of them. It is easy to
  arrive at, too: the build commit comes from git HEAD while make compares file
  times, so a commit can leave two binaries disagreeing about a commit while
  agreeing about every line of code.

- **`iyi mod diff` says whether a change reaches a module's consumers.** The
  three hashes an artifact carries already answered it and nothing asked them.
  It compares two `.iyimod` files, says which of interface, implementation and
  source moved — with what each of the three means, because the middle one is
  the surprising one — and names the exports that came and went when the
  interface is what moved. `--exit-code` exits 1 in that case, which is
  `git diff`'s spelling and its reason: the answer is not a failure.

- **An iyi program is run on three targets every build, not one.** It compiled
  for nine and was tested on one, which is a weak thing to call portability.
  CI now cross-compiles `hello.iyi` for musl and for aarch64, links each with
  the target's own `cc` and `libgc` (the command `--cross-compile` prints)
  and runs them: in an Alpine container and under emulation. The check is that
  each prints what the same program printed on the machine that compiled it.

- **`bench/runtime.py` measures what the library costs at run time.** The two
  libraries are within noise where they do the same work; `Hash` is 5x ahead
  and does less; `String` is 3.62x behind with the collector off. The first
  reading said string building was twenty times faster, and it was the
  collector, so the bench reports both columns and the honest one is the
  second. A later run no longer shows the twenty; as they run, string
  building is within noise, and the collector is masking a slower builder.

- **iyi describes itself as its own language, compatible with Crystal.** "A
  language built for Developer & Agentic Experience, Portability, Performance,
  and Efficiency", and README says what stands behind each of the four and what
  does not: the edit loop and the artifact are built, portability means nine
  targets that compile and three that are run, the run-time measurement is new
  and says the two libraries are within noise where they do the same work, and
  the agentic claim is a mechanism rather than a result.

  Compatibility is stated as something checkable and in one direction: the same
  compiler builds `.cr` files, an iyi program can `require` a shard with
  `--crystal`, and a Crystal program cannot require an iyi module, because R-2's
  written types and R-3's closed types are what an artifact is made of.

  `iyi version` reads `iyi 0.2.0-dev (built on Crystal 1.22.0-dev …)`: the
  language first and what it is built on after. The licence and NOTICE.md are
  unchanged, because Apache 2.0's attribution is an obligation rather than a
  description.

- **An artifact is read by the release that wrote it, not by the build.** A
  `.iyimod` was locked to the exact compiler build, commit and all, so two
  builds of the same version refused each other's modules and handing one to
  somebody meant handing them your compiler too. The identity is now the
  released version, the target and the flags. Every build of the same released
  version reads every other's artifacts on the same target under the same
  flags. A `-dev` version keeps the commit because it names no release. The
  version comes from `src/IYI_VERSION`, which is also what the binary reports
  and names the tarball.

- **A plain build using iyi's own prelude reaches no third-party library.**
  On macOS and Linux it needs no libgc and links only the platform libc. On
  macOS its undefined symbols are five libc calls (`write`, `exit`, `memset`,
  `malloc`, `realloc`), where 0.1.0's list was seven and four belonged to the
  allocator. On Linux the prelude now issues raw syscalls for `write`, `exit`
  and the allocator (`mmap`), so a Linux program's object asks libc for
  nothing at all. The linked executable still carries the five references its
  link template leaves, named below.

  The price is that the default does not collect. The prelude's allocator
  selection is inverted: a plain build binds `src/gc/none.cr`, which allocates
  over `malloc` and `realloc` and never frees. `-Dgc_boehm` opts back into real
  collection (`libgc.1.dylib` and the four `GC_*` symbols, exactly as before),
  and `-Dgc_none` still works and selects the default allocator. The flag used
  to be accepted and ignored because the prelude declared `@[Link("gc")]`
  directly. That was fixed first, then the default was flipped.

  The compiler lost `libiconv` (the Makefile passes `-Dwithout_iconv`) and
  `libpcre2`, and keeps `libgc`. `-Dgc_none` was tried on the compiler itself
  and is not viable: it emits invalid IR ("Load operand must be a pointer",
  from `LLVM::Module#verify`) on some runs and dies in `main_user_code` on
  others, being a long walk over ASTs with parallel codegen and fibers under
  an allocator that never frees. How pcre2 came off, and what it cost, is in
  the regex entry below.

  `bench/dependency_floor.sh` checks linked libraries beside symbols for a
  default build with iyi's own prelude and for `-Dgc_boehm`, and fails when
  either grows. It checks the compiler binary too, against an allowlist and a
  denylist that now carries `libpcre`. It does not build `--crystal`; that mode
  links Crystal's standard library and may pull every library a required shard
  pulls, so the zero-third-party-library claim and the floor gate do not apply
  to it.

  The gate reads a binary's own direct dependencies on both host platforms:
  `otool -L` load commands on macOS, and `readelf -d` NEEDED entries on Linux.
  `ldd` was on the Linux path and read the transitive closure instead, so
  libLLVM's dependencies counted as iyi's and the Linux compiler appeared to
  link libxml2, libz, libffi, libedit, icu, zstd, lzma, libbsd, libmd and
  libtinfo, while macOS showed none of it. The two platforms were measuring
  different claims, and the wide reading had no teeth: an allowlist holding
  libxml2 because libLLVM brings it can never catch iyi reaching for libxml2
  itself, which is the only case the denylist exists for. Proven both ways:
  rebuilding the compiler with an explicit `-lxml2` fails the gate by name,
  the same library inside libLLVM passes, and `otool -L` on `libLLVM.dylib`
  shows it beside libffi, libedit and libz. `linux-vdso.so.1` left the output
  without being allowed by anything: it was never a `DT_NEEDED` entry, the
  kernel maps it, and `ldd` was merely saying so.

  iyi is no longer Linux x86-64 only. One compiler cross-compiles for seven
  audited triples on four platforms: Linux x86_64 and aarch64, macOS x86_64
  and aarch64, Windows msvc and gnu, and wasm32-wasi. The own-prelude floor
  held on every one, measured with `llvm-nm --undefined-only` against the
  artifact each target actually emits (`.o` for ELF and Mach-O, `.obj` for
  Windows, `.wasm` for wasm32), two programs per triple. This is an emitted
  object audit, not a claim that the test suite runs on every target.

  At the object layer, Linux x86_64 and aarch64 leave no undefined symbols at
  all. macOS x86_64 and aarch64 leave `exit`, `malloc`, `memset`, `realloc` and
  `write`, all from libSystem. Windows msvc leaves `ExitProcess`,
  `GetProcessHeap`, `GetStdHandle`, `HeapAlloc`, `HeapReAlloc` and `WriteFile`,
  all from kernel32, and the gnu triple adds `main`. wasm32-wasi leaves
  `wasi_fd_write` and `wasi_proc_exit`, which are WASI imports. `malloc` and
  `realloc` are gone: the prelude binds `llvm.wasm.memory.grow.i32` as a
  two-argument `fun` and bump-allocates over grown pages. An earlier finding
  that Crystal could not reach `memory.grow` was an arity error, not an
  impossibility. The wasm linker globals (`memory_base`, `stack_pointer`,
  `table_base`, `indirect_function_table`) are linker plumbing, not
  dependencies.

  The linked executable is the other layer and it is not the same number. On
  Linux the program carries the five undefined references its C runtime
  objects leave behind, `__libc_start_main`, `__gmon_start__`,
  `__cxa_finalize` and the two weak `_ITM_` clone-table callbacks. They belong
  to the link template's `crt1.o`, `crti.o` and `crtbegin.o`, not the prelude.
  CI reported them on Linux, which is how this file learned that a claim
  measured on an object is not a claim about an executable. The gate allows
  those five by exact name, so `malloc` or `mmap` still fails: a wildcard would
  have been shorter, and "whatever the crt supplies" is not a measurable set,
  so it would also have hidden a prelude falling back to libc. The five were
  measured against the glibc in the container CI pins, and a different base
  contributes a different fixed set. Musl or an older glibc fails by name
  rather than passing, which is what a fixed-list check is for. On macOS the
  executable leaves the same five libSystem calls the object asked for. On
  both host platforms, an own-prelude program's dependency list is the
  platform libc and nothing else.

  The compiler binary links libLLVM, libc++, libgc and libSystem, and that is
  the whole direct list. `otool -L .build/iyi` prints those four;
  `.build/crystal`, the same compiler under its compatibility name, prints the
  same four. This is the compiler's own link line rather than everything that
  ends up mapped. What libLLVM pulls in beyond itself is LLVM's decision and
  the distribution's build. The floor is a property of what iyi builds rather
  than of what builds it, and the toolchain binary is now LLVM plus a collector
  plus the platform. SPEC.md III.9 records why the compiler keeps that
  collector, and III.10 records how pcre2 left.

- **Macro-level regex now runs on iyi's owned engine, with RE2 semantics.**
  `src/compiler/iyi/rx.cr` is differentially verified against pcre2
  (Appendix B #22). The price for a macro author is no in-pattern
  backreferences and no lookaround. A macro that uses one fails with a named
  error rather than meaning something else, and no pattern in a program or at
  compile time can take exponential time.

  `libpcre2` is off the compiler. `otool -L .build/iyi` lists libLLVM, libc++,
  libgc and libSystem, and `nm -u .build/iyi` leaves none of the thirteen
  `pcre2_*` symbols it used to. An earlier diagnosis blamed the leftover on
  the standard library prelude, assuming `require "regex"` emitted
  `@[Link("pcre2-8")]` even when nothing called it. That was wrong: an unused
  `@[Link]` does not put a library on the link line. The cause was ten reachable
  regex literals. `--emit llvm-ir` on the compiler shows ten expanded regex
  constants, `$Regex:0` through `$Regex:9`, whose patterns identify four
  standard library files the compiler compiles into itself.

  Those four now parse by hand, with no engine, and none calls `Crystal::Rx`,
  because the standard library does not reach into compiler internals:

  - `src/option_parser.cr`, seven literals in `parse_flag_definition`, reached
    from `compiler.cr`, `loader.cr` and most of `command/*`. A 20,633-case
    differential against the original seven regexes found 0 mismatches.
  - `src/process/shell.cr`, one literal in `Process.quote_posix`, reached
    because the compiler shells out to the linker. A 194,690-input
    differential covering every Unicode scalar to U+2FFFF found 0 mismatches,
    and 18 hostile arguments passed a live `/bin/sh` round trip.
  - `src/semantic_version.cr`, `VERSION_PATTERN`, reached from
    `macros/methods.cr` for `compare_versions`. `valid?` and `parse?` now share
    one scanner so they cannot drift. One existing asymmetry remains on
    purpose: `valid?("99999999999999999999999.1.1")` is true while `parse?`
    raises `ArgumentError` from `to_i`.
  - `src/spec/cli.cr`, two uses rather than one, reached because
    `command/spec.cr` requires `spec/cli` so `crystal spec --help` can print
    the runner's options. `--location` is one literal. `-e/--example` was
    `Regex.new(Regex.escape(pattern))`, which is substring matching written
    the long way.

  **`-e/--example` is a breaking change to a standard library public API.**
  `Spec::CLI#pattern` was `Regex?` and is now `String?`.
  `Spec::Item#matches_pattern?` and `filter_by_pattern` now take a `String`,
  with `=~` replaced by `includes?`. The behaviour is identical because
  `Regex.escape` had already reduced every pattern to a literal substring, but
  the type is not. Direct callers get a compile error rather than a
  deprecation.

  Two findings cost more to rediscover than the dependency. PCRE2 in this tree
  is compiled with `UCP`, so its `\s` is Unicode and `Char#whitespace?` is a
  different predicate. They agree on every character except U+0085 NEL, which
  `option_parser.cr` now names explicitly. The differential first reported
  1,114 mismatches, all containing U+0085. The same flag makes `\d` mean
  `\p{Nd}`, so `--location` used to accept a non-ASCII digit as a line number
  and deliberately no longer does. Second, in `/\A(.+?)\:(\d+)\Z/`, the lazy
  `(.+?)` reads as "shortest prefix" and is not one. `(\d+)\Z` has to reach
  the end and `:` is not a digit, so the engine backtracks until the last colon
  is the split. That makes `a:1:2` file `a:1`, line 2. A `split(':')`, or any
  leftmost scan, gets that wrong.

  The gate closed behind it. `libpcre2` came off
  `ALLOWED_LIBS_COMPILER` in `bench/dependency_floor.sh`, and `libpcre` went
  onto `FORBIDDEN`, so the compiler is held to the same denylist as
  own-prelude programs. Injecting a reachable regex literal back into
  `option_parser.cr` makes the gate exit non-zero at both layers, naming the
  gained library and the denylist hit. The first probe was discarded because
  it used an unused constant. Crystal does not instantiate an unreachable
  constant, so no library came back and that probe did not test the gate.

- **Appendix B #20 through #26 record the runtime decisions.** iyi writes its
  own garbage collector (#20), overruling the earlier plan to adopt gcry and
  pay it back in layouts. The owner's goal is control over concurrency,
  parallelism and performance, and owning the collector is the only path to
  it. gcry remains prior art: roughly 87% throughput at roughly 0.80x post-GC
  RSS against Boehm, with precise stack roots correctness-stable and not an RSS
  win. The bill is explicit: heap, stop-the-world, roots, finalizers and
  platforms are rebuilt in this tree. Until that collector serves parallel
  codegen, the compiler keeps bdw-gc (#24, superseded and restated).

  The default own-prelude build still allocates and never collects (#23), so a
  long-running program grows without bound. `-Dgc_boehm` is the opt-in.
  iyi's own prelude has no IO beyond `puts` and no concurrency. A
  `--crystal` program uses Crystal's standard library instead and is outside
  both that limitation and the own-prelude dependency floor.

### Added

- **`iyi build --crystal` compiles a program against Crystal's standard
  library, so `require` reaches the ecosystem.** A `.iyi` file refused
  `require` because there was nothing to require: the prelude is what a program
  gets. That reason stops being true when the prelude is Crystal's. The rules
  do not change with the library — the module header, `pub`, `import`, `using`,
  traits and `impl` are all still there, and a shard is ordinary Crystal
  compiled into the program.

  A Kemal server written this way serves HTTP. What it gives up is R-1 for that
  dependency: the shard is read from source, so the edit loop pays for it the
  way Crystal does. Your own modules are unaffected, and `--emit-iyimod` still
  writes them.

  `crystal tool bind` writes what it generates with `--emit-bind`, its own
  switch, because what it writes is a boundary for a shard rather than this
  build's own modules.

  The two libraries are two modes and do not mix on the artifact side:
  `--use-iyimod` and `--emit-iyimod` need iyi's own prelude. An artifact's
  object code numbers the types its module made, which under Crystal's library
  include the standard library's own, and a consumer compiling its own copy of
  that library has two of everything. That was an LLVM module which would not
  verify; it is a sentence now.

  **Nine shards were swept through it**, each built twice — as an iyi program
  and as a Crystal one, so that a difference is this fork's and a shared
  failure is the ecosystem's. `kemal`, `db`, `ameba`, `habitat`,
  `baked_file_system`, `radix`, `sqlite3`, the standard library's own
  `json`/`yaml`/`uri`/`http`, and a program that round-trips
  `JSON::Serializable` and writes a file. All nine behave the same in both
  languages. One needed a word changed and it was the rule working: `habitat`'s
  macro resolves the type it is handed by name, and a class an iyi module
  leaves unmarked is private, so it needs `pub class`.

  `samples/crystal/stdlib.iyi` is the program CI builds to keep this true: a
  trait with a default, an `impl` on a generic, an error union with `!` and
  `.or`, a `defer`, and JSON, YAML and URI in the same file.

- **`pub` takes a constant.** `pub LIMIT = 42` is reachable through the
  module's name; an unmarked constant is the module's own and is refused by the
  sentence an unmarked `def` gets. Nothing was added to the artifact format,
  because a module's top level already travels as source and the mark travels
  with it.

  The hole under it is the same one `pub macro` found: a constant's visibility
  was never set, so every constant a module declared was reachable. That is
  what a real shard leans on — Kemal hands out every object it has through one.

- **`pub macro`, so a macro can cross a module boundary.** Every macro a module
  writes already travelled in its artifact, because a body that travels may
  call one, but none of them was reachable: `pub` did not take a macro. A
  marked one is now reachable exactly as a `pub def` is, unqualified after
  `using` or through the module's name, and it works against an artifact with
  the module's source deleted. What it exports is a name and an arity, because
  a macro takes syntax and returns syntax.

  Two things worth knowing. Closing this found the hole under it: a macro's
  visibility was never set, so **every** module's macros were already callable
  through its name — that is refused now, with the sentence an unexported `def`
  gets. And macros are not hygienic, so a `pub macro` that writes `tmp = 99`
  assigns to the consumer's `tmp`; SPEC.md IV.4 says so in full.

- **`iyi tool format` formats iyi.** The formatter is Crystal's and knew none
  of iyi's syntax, so a module header, a `pub`, a `trait`, an `impl`, a
  `using`, a bounded `forall`, a `where`, a `defer`, a `!` or an `.or` sent it
  into "there's a bug formatting this file". It knows all of them now, and a
  directory is searched for `.iyi` files as well as `.cr` ones. The prelude and
  the nine samples format to themselves, which is the test that made the last
  three of those show up.

- **`iyi repl` brings the interpreter back on a smaller base** (Appendix B
  #25, reopening #11). It starts, reads a line, evaluates it on the 781-line
  macro interpreter, prints the result, and survives a bad line. Session
  variables persist across lines. Each line is a fresh parse unit, so a bare
  `x` is a Call until the REPL rewrites names it already holds into Vars. This
  is not the 11,377-line revert, which cannot run an iyi program past its
  module header.

  There is no C interop, so no libffi, and the own-prelude floor enforces that:
  libffi is on `bench/dependency_floor.sh`'s denylist. Adding to a sample the
  exact `@[Link("ffi")]` shape a naive revert would produce failed at three
  independent layers, reporting the gained symbol `ffi_prep_cif`, the gained
  library `libffi.8.dylib`, and the denylist hit.

- **wasm32 grows its own heap** (Appendix B #26). The own prelude binds
  `llvm.wasm.memory.grow.i32` as a two-argument `fun` (memory index, then page
  delta) and bump-allocates over the grown pages. `malloc` and `realloc` are
  gone from the emitted `.wasm`; the remaining undefined symbols are the WASI
  imports `wasi_fd_write` and `wasi_proc_exit`, plus linker globals. An earlier
  probe used the one-argument form, failed verification, and was misread as
  "Crystal cannot bind this intrinsic". The two-argument form lowers to
  `memory.grow 0`. Accepting wasi-libc as the platform runtime, or documenting
  wasm32 as a qualified target, were both rejected.

### Fixed

- **A generic imported from an artifact links again when its type argument is
  inferred.** `Box(Int32).new(42)` always worked and `Box.new(42)` did not.
  Inference makes `new` a method on `Box(T)`, which is the artifact's own type,
  and the rule that says "this type's machine code is in the artifact" was
  reading the generic itself. An artifact carries a unit for every non-generic
  type a module declares and none for a generic one, because a generic has
  machine code only once somebody picks its arguments, and the consumer is who
  picks them. So the consumer declared a `new` that nothing defined and the
  program failed to link, saying `undefined reference to Box(T)::new<Int32>`.
  The consumer's rule now matches the producer's. Reported after 0.1.0 went
  out.

- **`Array#sort` sorts the array, and `sorted` hands back a copy.** SPEC.md
  III.1.7(A) settled that pair — the plain verb mutates, the participle copies,
  Swift's convention adopted because `!` had to leave identifiers so postfix
  `!` could propagate an error — and the prelude did not implement it: `sort`
  returned a copy and nothing mutated. It does now, and `sorted` is one line
  over it.

  Worth knowing when moving between the two libraries: Crystal names the same
  pair `sort!` and `sort`, so `a.sort` copies there and sorts here. It is the
  one call in this prelude that means something different under `--crystal`,
  and the note is in `src/iyi/array.iyi` where somebody is standing when it
  matters.

- **A `using` that cannot deliver is refused where it is written.** A module
  header makes a type, and inside it that name means the module — so
  `using app/count::{Tally}` in a module called `tally` asks for a name it
  cannot have. What it said before was that `Tally` was not
  `App::Count::Tally`, at the first line that used one, with nothing pointing
  at the directive. Found by writing a command-line program.

- **`String#size` counts when nobody counted.** Crystal reads `@length == 0` on
  a non-empty string as "not counted yet" and scans; this prelude returned the
  field. A string built by Crystal's own `to_json` therefore printed correctly
  through iyi's `puts` and answered `size` **0** — no error, a wrong number.
  Free for every string this prelude makes, because it fills the field. Found
  while measuring what crosses between the two languages.

- **A macro that cannot see a type says why.** An unresolved path stays a
  `Path`, so every method a macro would call on the type is undefined on that,
  and the message named `Path` rather than the type or the rule:
  `undefined macro method 'Path#constant'`. It now asks whether the path names
  a type that exists and is unexported, and says so when it does. Found by
  `habitat`.

- **The front end reads a `.iyi` file again.** Refusing `require` in a `.iyi`
  file spares the prelude's own, and the flag that says so was set in the
  driver but not in `crystal-front`, so the front-end binary refused the line
  it had just written itself. It is bench-only and ships in nothing.

- **A version bump takes effect.** `src/VERSION` and `src/IYI_VERSION` are
  compiled in with `read_file`, and the build did not depend on them, so
  changing the number changed nothing until something else did.

## 0.1.0 — 2026-08-18

The first release. There is nothing to compare it against, so this says what is
in it rather than what changed, and what a later version will have to keep
faith with.

### The language

Four rules, and everything else follows from them (SPEC.md):

- **R-1** A module is the unit of compilation. `import` forms a DAG, and
  compiling a module reads its imports' declarations, never their bodies.
- **R-2** Everything a module exports (`pub`) writes down full parameter and
  return types.
- **R-2b** `using` brings exported names into unqualified scope, written by the
  consumer.
- **R-3** No open classes. `impl Trait for Type` lives in the module that
  declares the trait or the one that declares the type.

Traits with defaults and associated types, generic impls with `forall`, errors
as ordinary union members with `!` propagation, `defer` scoped to the block,
and Crystal's syntax otherwise: union types, nil-safety, blocks, local
inference, macros.

### The artifact

0.1.0 shipped `.iyimod` **format v19**: declarations, macros, bodies that have
to travel, object code, and a checksum per section. Its artifacts were locked
to the exact compiler build, so another build refused and rebuilt them rather
than migrating them. The 0.2.0 rule above replaces that build identity with
released version, target and flags, while development versions keep the commit.

`iyi build --emit-iyimod DIR` writes them, `--use-iyimod DIR` builds against
them, and `iyi mod dump` prints one as text.

### The tool

`iyi` takes `build`, `run`, `mod`, `env`, `clear_cache`, `tool`, `version` and
`help`. `crystal` is the same compiler under its own name, and it still
compiles `.cr` files. `eval` is deliberately not on iyi's list: it has no
filename, so it gets Crystal's prelude and Crystal's rules, and a command that
answers in another language is worse than one that says where it went.

### Measured

One machine, release compiler, best of seven, seconds. A 30-module,
7,208-line project, rebuilt after changing one line in one module:

| | iyi | Crystal | `go build` |
|---|---|---|---|
| rebuild after one edit | **0.13** | 1.17 | 0.16 |

The same edit with every module read from source instead of from artifacts
costs 0.23 s, which is what R-1 is worth on this project. A full build of a
6,900-line program from scratch is 0.24 s against `go build`'s 0.09 s, which is
where iyi loses. `python3 bench/incremental.py` and `python3
bench/build_speed.py` print both, and refuse to time programs that do not agree
on their output.

### Not in this release

iyi's own 0.1.0 prelude had no IO beyond `puts` and no concurrency; SPEC.md
III.4 specified concurrency and none was built. There was no package manager,
standard library or self-hosting, and the release supported Linux x86-64 only.
`derive` macros did not cross modules. The own prelude was 1,184 lines, its
collections were small, and `a[-1]` raised rather than indexing from the end.
The formatter did not know iyi's syntax: `iyi tool format` said so and left
`.iyi` files alone.

### Provenance

A fork of [Crystal](https://github.com/crystal-lang/crystal) at 1.22.0-dev,
Apache 2.0 with Swift exception, Copyright 2012-2026 Manas Technology
Solutions. The backend, the GC and the type checker are Crystal's work. The
compiler reports itself as `Crystal 1.22.0-dev` because that is what it is, and
it is bootstrapped by released Crystal 1.21.0, which is the version CI pins
and the one to install if you are building this from source.

Two bugs in Crystal's own compiler were found here and fixed in this fork; they
belong upstream and are separate commits for that reason:

- `Crystal.relative_filename` chopped the working directory off any path that
  merely began with its name, so a build in `/x/crystal` with a cache in
  `/x/crystal-cache` wrote its object files to `-cache/…`.
- The cache cleaner deleted the directory of a build that was still running,
  because it keeps the ten most recently modified directories and a build stops
  looking recent while its units sit in an optimization pass.
