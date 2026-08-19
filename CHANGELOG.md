# Changelog

## Unreleased

An iyi program needs no libgc. A plain `iyi build` links the platform libc and
nothing else, and its undefined symbols are five libc calls (`write`, `exit`,
`memset`, `malloc`, `realloc`) where 0.1.0's list was seven, four of them the
allocator. On Linux the prelude now issues raw syscalls for `write`, `exit` and
the allocator (`mmap`), so a Linux program should need no libc at all.

The price is that the default does not collect. The prelude's allocator
selection is inverted: a plain build binds `src/gc/none.cr`, which allocates
over `malloc` and `realloc` and never frees, `-Dgc_boehm` opts back into real
collection (`libgc.1.dylib` and the four `GC_*` symbols, exactly as before),
and `-Dgc_none` still works and selects the default's allocator. The flag used
to be accepted and ignored, because the prelude declared `@[Link("gc")]`
directly; that was fixed first, then the default was flipped.

The compiler lost `libiconv` (the Makefile passes `-Dwithout_iconv`) and
keeps `libgc` and, still, `pcre2`. `-Dgc_none` was tried on the compiler
itself and is not viable: it emits invalid IR ("Load operand must be a
pointer", from `LLVM::Module#verify`) on some runs and dies in
`main_user_code` on others, being a long walk over ASTs with parallel
codegen and fibers under an allocator that never frees. Compiler source
no longer calls the stdlib `Regex`: macro-level regex runs on
`src/compiler/crystal/rx.cr` (Appendix B #22). The binary still links
`libpcre2-8.0.dylib` because Crystal's prelude `require "regex"` is
enough to emit `@[Link("pcre2-8")]`. That leftover is a later commit,
not a silent pass.
`bench/dependency_floor.sh` now checks the linked libraries beside the
symbols, for the default build and for `-Dgc_boehm`, and fails when either
grows.

iyi is no longer Linux x86-64 only. One compiler now emits for seven triples
on four platforms: Linux x86_64 and aarch64, macOS x86_64 and aarch64, Windows
msvc and gnu, and wasm32-wasi. The floor held on every one, measured rather
than promised: `llvm-nm --undefined-only` against the artifact each target
actually emits (`.o` for ELF and Mach-O, `.obj` for Windows, `.wasm` for
wasm32), three programs per triple.

Linux x86_64 and aarch64: no undefined symbols at all. Not "no libc", nothing,
which is what the raw-syscall paragraph above projected, now measured on the
emitted objects. macOS x86_64 and aarch64: `exit`, `malloc`, `memset`,
`realloc`, `write`, all libSystem. Windows msvc: `ExitProcess`,
`GetProcessHeap`, `GetStdHandle`, `HeapAlloc`, `HeapReAlloc`, `WriteFile`, all
kernel32, and the gnu triple adds `main`. wasm32-wasi: `wasi_fd_write` and
`wasi_proc_exit`, which are WASI imports. `malloc` and `realloc` are gone:
the prelude binds `llvm.wasm.memory.grow.i32` as a two-argument `fun` and
bump-allocates over grown pages. An earlier finding that Crystal cannot
reach `memory.grow` was an arity error, not an impossibility. The wasm
linker globals (`memory_base`, `stack_pointer`, `table_base`,
`indirect_function_table`) are linker plumbing, not dependencies.

The compiler binary still links libLLVM, libc++, libpcre2, libgc and
libSystem. The floor is a property of what iyi builds rather than of
what builds it. SPEC.md III.9 records why the compiler keeps its own
collector, and why pcre2 has not yet left the toolchain binary.

Five decisions are recorded in SPEC.md Appendix B #20 through #26.

Macro-level regex now runs on iyi's own engine, `src/compiler/crystal/rx.cr`,
with RE2 semantics, differentially verified against pcre2 (#22). Compiler
source no longer constructs a stdlib `Regex`. The compiler binary still
links libpcre2, because the Crystal prelude's `require "regex"` emits
`@[Link("pcre2-8")]` even when nothing calls it. What it costs a macro
author: no in-pattern backreferences, no lookaround. A macro that uses
one fails with a named error rather than quietly meaning something else,
and no pattern, in a program or at compile time, can take exponential
time.

iyi writes its own garbage collector (#20), overruling the earlier plan to
adopt gcry and pay it back in layouts. The goal is the owner's: control over
concurrency, parallelism and performance, and owning the collector is the
only path to it; gcry was hints about what has already been tried to pull
Crystal off Boehm, and its measurements (~87% throughput at ~0.80x post-GC
RSS against Boehm; precise stack roots correctness-stable and not an RSS
win) are inherited as prior art rather than repeated. The bill is the bill:
heap, stop-the-world, roots, finalizers and platforms are rebuilt in this
tree. Until that collector reaches the stage that serves parallel codegen,
the compiler keeps bdw-gc (#24, superseded and restated). The default build
still allocates and never collects (#23): a long-running program grows
without bound, `-Dgc_boehm` is the opt-in, and no 0.1.0 program is
long-running, because there is no IO beyond `puts` and no concurrency.

The interpreter comes back, on a different base (#25, reopening #11):
`iyi repl` starts, reads a line, evaluates it on the 781-line macro
interpreter, prints the result, and survives a bad line. Session
variables persist across lines: each line is a fresh parse unit, so a
bare `x` is a Call until the REPL rewrites names it already holds into
Vars. Not the 11,377-line revert, which cannot run an iyi program past
its module header. No C interop, so no libffi, and that is enforced:
libffi is on `bench/dependency_floor.sh`'s denylist, and the gate was
proven to fire by adding to a sample the exact `@[Link("ffi")]` shape a
naive revert would produce. It failed at three independent layers,
reporting the gained symbol `ffi_prep_cif`, the gained library
`libffi.8.dylib`, and the denylist hit.

wasm32 grows its own heap (#26). The prelude binds
`llvm.wasm.memory.grow.i32` as a two-argument `fun` (memory index, then
page delta) and bump-allocates over the grown pages. `malloc` and
`realloc` are gone from the emitted `.wasm`; the remaining undefined
symbols are the WASI imports `wasi_fd_write` and `wasi_proc_exit`, plus
linker globals. An earlier probe used the one-argument form, failed
verification, and was misread as "Crystal cannot bind this intrinsic".
The two-argument form lowers to `memory.grow 0`. Accepting wasi-libc as
the platform runtime, or documenting wasm32 as a qualified target, were
both rejected.

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

`.iyimod` **format v19**. A module's declarations, its macros, the bodies that
have to travel, its object code, and a checksum per section. Artifacts are
version-locked: one written by another build of the compiler is refused and
rebuilt, never migrated, so a later version bumping this number is expected
rather than a breakage.

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

No IO beyond `puts`. No concurrency: SPEC.md III.4 specifies it and none of it
is built. No package manager, no standard library, no self-hosting. Linux
x86-64 only. `derive` macros do not cross modules. The prelude is 1,184 lines
and its collections are small, and `a[-1]` raises rather than indexing from the
end. The formatter is Crystal's and does not know iyi's syntax: `iyi tool
format` says so and leaves `.iyi` files alone.

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
