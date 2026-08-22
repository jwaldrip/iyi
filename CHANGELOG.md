# Changelog

## Unreleased

### Added

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

### Fixed

- **A constant an artifact reads carries a location.** The reads a consumer
  performs on an artifact's behalf were synthesised without one, and LLVM
  refuses a call with no location inside a function that has debug info. It
  never fired under iyi's own library and fired at once under Crystal's, which
  is where it was found — while looking at whether artifacts and `--crystal`
  can be used together. They still cannot, but the reason recorded in SPEC.md
  Part V item 12a was wrong and is now the measured one.

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
