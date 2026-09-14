# The Stage One Contract

What stage one actually requires, the dependency order of the components,
the blockers for each component today, and the observable proof of stage one.

Every number and claim in this document cites a measured file or command
output from this repository, verified by `python3 bench/doc_numbers.py`
and the selfhost exercise suite.

## 1. What Stage One Is

`BOOTSTRAP.md` defines four bootstrapping stages:

* **Stage 0 (the contract):** No self-hosted compiler is built. The compiler
  is built by Crystal from Crystal sources in `src/compiler/iyi/*.cr`. Ported
  components in `src/compiler/**/*.iyi` are exercised against the Crystal
  frontend via differential gates.
* **Stage 1 (the bootstrap cutover):** A compiler binary built by Crystal from
  pure iyi sources in `src/compiler/**/*.iyi`. This binary is compiled by the
  Crystal-hosted compiler (`bin/iyi`), but its entire source code is written in
  iyi. Its output is the thing under test, never its own source.
* **Stage 2 (first self-compilation):** The stage-one compiler compiles the same
  iyi sources (`src/compiler/**/*.iyi`) to produce stage two. This is the first
  moment iyi is compiled by an iyi binary.
* **Stage 3 (fixed point):** The stage-two compiler compiles the same sources to
  produce stage three. `cmp -s .build/iyi-stage2 .build/iyi-stage3` must be
  byte-identical.

The standing objective of self-hosting is eliminating `libgc`. Running
`bash bench/dependency_floor.sh` confirms that user programs built by iyi link
only `libSystem.B.dylib` on macOS (the platform libc). However, `bin/iyi`
itself still links:

```
libc++.1.dylib libgc.1.dylib libLLVM.dylib libSystem.B.dylib
```

The compiler links `libgc` only because it is a Crystal program and Crystal's
runtime requires Boehm GC. A self-hosted compiler written in iyi uses iyi's own
allocator and runtime (`src/iyi/prelude.iyi`), eliminating `libgc` completely.

## 2. Measuring the Real Gap Today

As measured by `python3 bench/doc_numbers.py`, the compiler source consists of:

* **110,105 lines of Crystal** across 177 files in `src/compiler/**/*.cr`
  and top-level wrappers (`crystal.cr`, `iyi.cr`, `crystal_front.cr`).
* **41,496 lines of pure iyi** across 51 files in `src/compiler/**/*.iyi`.

### Verification of the `BOOTSTRAP.md` Claim

`BOOTSTRAP.md` stated:

> Nothing in the build calls any of the ports above yet: each is checked against
> the code it would replace, not used in its place.

Verification of `Makefile`:
* `$(O)/iyi$(EXE)` compiles `src/compiler/iyi.cr` via `./bin/crystal build`.
* `$(O)/crystal$(EXE)` compiles `src/compiler/crystal.cr` via `./bin/crystal build`.
* `$(O)/crystal-front$(EXE)` compiles `src/compiler/crystal_front.cr`.
* `src/compiler/requires.cr` requires only `./iyi/*`, `./iyi/semantic/*`,
  `./iyi/macros/*`, and `./iyi/codegen/*` (all `.cr` files).

Prior to this work, no build rule, no compiler pipeline pass, and no CLI command
called any `.iyi` file under `src/compiler/`. Each port was only compiled during
isolated gate runs in `bench/selfhost_*_exercise.sh` where a standalone test
harness imported a single ported module and compared its output against a Crystal
oracle script.

The first three wiring steps have now been implemented: `bin/iyi mod dump --selfhost`
wires `src/compiler/artifact/iyimod.iyi` into the shipped compiler CLI,
`bin/iyi tool format --selfhost` wires `src/compiler/tools/formatter.iyi` into
the shipped compiler CLI, and `bin/iyi check --parse-only --selfhost` wires
the ported front end (`src/compiler/syntax/parser.iyi` and `syntax/lexer.iyi`) into
the shipped compiler CLI.
## 3. Component Inventory and Blockers

Below is the complete status of all twenty ported and unported compiler
subsystems, their line counts, and what blocks each from being wired into
the compiler pipeline today:

### Layer 0: Foundation
* **`foundation/*.iyi` (122 lines across 4 files) vs `src/compiler/iyi/` foundation types**
  * Ported: `location.iyi`, `errors.iyi`, `enums.iyi`, `string_pool.iyi`.
  * Status: Tested by `bench/selfhost_lexer_exercise.sh` and downstream gates.
  * Wiring: Unwired directly into CLI. Consumed by downstream components.
  * Blockers: Foundation types are ready. Blocked only on downstream consumers.

### Layer 1: Lexer and AST
* **`syntax/lexer.iyi`, `syntax/token.iyi` (3,468 lines across 2 files) vs `src/compiler/iyi/syntax/lexer.cr` (1,939 lines)**
  * Status: 44 fixtures, 21,206 tokens identical to Crystal frontend.
  * Wiring: Wired behind `iyi check --parse-only --selfhost` via companion tool `iyi-parse`.
  * Blockers for compilation pipeline: In-memory runtime boundary. Crystal's `Parser` (`parser.cr`)
    instantiates `Iyi::Lexer` in-process. Replacing `Iyi::Lexer` inside Crystal
    with `Lexer.iyi` requires an in-process FFI bridge between incompatible
    runtimes (Boehm GC vs pure-iyi heap) or a token serialization protocol over
    a pipe. It must be wired together with `Parser.iyi` in pure iyi.
* **`syntax/ast.iyi`, `visitor.iyi`, `transformer.iyi` (7,217 lines across 3 files) vs `src/compiler/iyi/syntax/ast.cr` (4,482 lines)**
  * Status: 104 concrete AST node kinds verified by `bench/selfhost_ast_exercise.sh`.
  * Wiring: Consumed by companion tools (`iyi-parse`, `iyi-format`).
  * Blockers for compilation pipeline: Central in-memory data structures. Consumed by semantic analysis
    and codegen. Cannot replace Crystal's AST nodes until semantic analysis and
    codegen are assembled in pure iyi.

### Layer 2: Parser and Normalizer
* **`syntax/parser.iyi` (5,171 lines) vs `src/compiler/iyi/syntax/parser.cr` (7,600 lines)**
  * Status: 26 fixtures, 1,715 normalized nodes identical to Crystal frontend.
  * Wiring: Wired behind `iyi check --parse-only --selfhost` via companion tool `iyi-parse`
    (verified by `bench/selfhost_parser_wiring_exercise.sh`).
  * Blockers for compilation pipeline: Produces `ast.iyi` nodes rather than `ast.cr` nodes,
    blocked by the in-process heap boundary from being consumed by Crystal's semantic analysis.
* **`semantic/normalizer.iyi` (705 lines) vs `src/compiler/iyi/semantic/normalizer.cr` (1,236 lines)**
  * Status: 11 fixtures, 577 normalized nodes identical to Crystal frontend.
  * Wiring: Unwired into CLI.
  * Blockers: Transforms `ast.iyi` nodes in memory. Blocked on the in-process heap boundary.

### Layer 3: Macro Expansion
* **`macros/*.iyi` (1,614 lines across 5 files) vs `src/compiler/iyi/macros/*.cr` (4,396 lines)**
  * Status: 12 fixtures, 71 expanded nodes verified by `bench/selfhost_macros_exercise.sh`.
  * Wiring: Unwired into CLI.
  * Blockers:
    1. In-process heap boundary.
    2. `TypeNode` semantic inspection: accessing type tables from macros.
    3. External macro execution (`macro run`).
    4. Semantic hook callbacks (`inherited`, `included`, `extended`).

### Layer 4: Type System and Semantic Analysis
* **`types/*.iyi` (2,115 lines across 6 files) vs `src/compiler/iyi/types.cr` (3,800+ lines)**
  * Status: 7 fixtures, 66 types verified by `bench/selfhost_types_exercise.sh`.
  * Wiring: Unwired into CLI. Blocked on semantic analysis and the in-process heap boundary.
* **`semantic/top_level.iyi`, `semantic/main_visitor.iyi`, `semantic/recursive_struct_checker.iyi` (3,273 lines across 3 files) vs `src/compiler/iyi/semantic/*.cr` (25,000+ lines)**
  * Status: 25 error fixtures, 9 feature fixtures (39 declarations), 16 typed expression fixtures (390 typed nodes), 21 mutation proofs.
  * Ported: Instance variable type inference across a type, class variable initializers, recursive struct check, overload resolution by argument types with specificity ranking and autocast ambiguity detection, multiple dispatch over union receivers, block and closure type inference.
  * Wiring: Unwired into CLI.
  * Blockers: In-process heap boundary and unported components in Crystal:
    1. First-class captured proc values and closure lifting (`Proc(T, R)` allocation).
    2. Exception handling typing (`exception_handler.cr`).
    3. `TypeNode` semantic inspection in macros (`src/compiler/iyi/macros/types.cr`).

### Layer 5: Platform and LLVM C-API
* **`platform/*.iyi` (698 lines across 3 files) vs `src/compiler/iyi/codegen/target.cr` and `compiler.cr`**
  * Status: 24 target triples verified by `bench/selfhost_platform_exercise.sh`.
  * Wiring: Unwired into CLI. Consumed by compiler driver and linker invocation.
* **`llvm/*.iyi`, `llvm.iyi` (2,365 lines across 10 files) vs Crystal LLVM bindings**
  * Status: Verified in `bench/selfhost_codegen_exercise.sh` and `bench/selfhost_compile_exercise.sh`.
  * Wiring: Unwired into CLI. Consumed by codegen.

### Layer 6: Code Generation
* **`codegen/codegen.iyi` (4,611 lines) vs `src/compiler/iyi/codegen/*.cr` (15,000+ lines)**
  * Status: 18 fixtures, 108 functions with identical LLVM IR and execution verified by `bench/selfhost_codegen_exercise.sh`.
  * Ported: Functions, structs, classes, virtual dispatch, nilable, blocks, exceptions, closures, string literals, generics, heap layouts, and runtime symbols.
  * Wiring: Unwired into CLI.
  * Blockers: Generics monomorphization, GC interface integration, and in-process heap boundary.

### Layer 7: Artifact Serializer
* **`artifact/iyimod.iyi` (2,681 lines) vs `src/compiler/iyi/iyimod.cr` (1,348 lines)**
  * Status: 16 modules, 80,414 bytes, 100% byte-for-byte parity, cross-reading,
    refusal verified by `bench/selfhost_iyimod_exercise.sh`.
  * Wiring: Wired behind `bin/iyi mod dump --selfhost` via companion tool `iyi-mod`
    (verified by `bench/selfhost_mod_wiring_exercise.sh`).
  * Blockers for compilation pipeline: Standalone dumping is fully wired. In-pipeline artifact writing requires semantic analysis.

### Layer 8: Command Driver and Tooling
* **`command/driver.iyi` (1,970 lines) vs `src/compiler/iyi/command.cr` (1,104 lines)**
  * Status: 115 argument vectors verified by `bench/selfhost_command_exercise.sh`.
  * Wiring: Unwired into CLI.
  * Blockers: Option parsing and dispatch only. Cannot compile programs until
    the full compiler pipeline is wired.
* **`command/daemon.iyi` (717 lines) vs `src/compiler/iyi/command/daemon.cr` (537 lines)**
  * Status: 30 scenarios verified by `bench/selfhost_daemon_exercise.sh`.
  * Wiring: Unwired into CLI.
  * Blockers: Socket paths and identity only. Does not implement worker fork loop.
* **`tools/formatter.iyi` (2,436 lines) vs `src/compiler/iyi/tools/formatter.cr` (5,457 lines)**
  * Status: 35 files verified in `bench/selfhost_formatter_exercise.sh`.
  * Wiring: Wired behind `bin/iyi tool format --selfhost` via companion tool `iyi-format`
    (verified by `bench/selfhost_format_wiring_exercise.sh`).
* **`tools/bind.iyi` (1,213 lines) vs `src/compiler/iyi/tools/bind.cr`**
  * Status: 11 fixtures in `bench/selfhost_bind_exercise.sh`.
  * Wiring: Unwired into CLI.
  * Blockers: Works from parsed AST rather than semantically analyzed types and LLVM data layout for `size_of`.
    Cannot bind real shards until semantic analysis lands.
* **`compiler.iyi`, `loader.iyi`, `tools/compile.iyi` (1,112 lines across 6 files)**
  * Status: 14 whole-program fixtures verified by `bench/selfhost_compile_exercise.sh`.
  * Wiring: Standalone tool `.build/iyi-compile` exists. Unwired into shipped compiler `bin/iyi build`
    because it only compiles with `--prelude=empty` and cannot compile the full prelude yet.

### Current Wiring Summary

| Component | Ported Lines | Shipped Crystal Lines | Wiring Status | Gating Script |
|---|---|---|---|---|
| Artifact Dumper (`iyimod.iyi`) | 2,681 | 1,348 | Wired (`bin/iyi mod dump --selfhost`) | `bench/selfhost_mod_wiring_exercise.sh` |
| Formatter (`formatter.iyi`) | 2,436 | 5,457 | Wired (`bin/iyi tool format --selfhost`) | `bench/selfhost_format_wiring_exercise.sh` |
| Parser/Lexer (`parser.iyi`) | 8,639 | 9,539 | Wired (`bin/iyi check --parse-only --selfhost`) | `bench/selfhost_parser_wiring_exercise.sh` |
| Bind Tool (`bind.iyi`) | 1,213 | ~5,600 | Not wired (unproven on real shards) | `bench/selfhost_bind_exercise.sh` (standalone only) |
| End-to-End Compiler (`compile.iyi`) | 1,112 | ~15,000 | Not wired (only compiles with `--prelude=empty`) | `bench/selfhost_compile_exercise.sh` (standalone only) |
| Compilation Pipeline (AST/Semantic/Codegen) | 25,415 | ~88,000 | Not wired (blocked by heap boundary) | Individual standalone gates |
## 4. The Stage One Wiring Sequence

To achieve Stage One, components must be wired in strict topological dependency
order:

```
[Layer 0: Foundation]
       |
       v
[Layer 1: Lexer + Token + AST + Visitor]
       |
       v
[Layer 2: Parser + Normalizer] <-----+
       |                             |
       v                             |
[Layer 3: Macro Parser + Engine] ----+
       |
       v
[Layer 4: Types + Semantic Analysis (TopLevel, Visitors, Inference, Overloads)]
       |
       v
[Layer 5: Platform Support + LLVM C-API Bindings]
       |
       v
[Layer 6: Code Generation (Fun, Classes, Closures, Exceptions, GC)]
       |
       v
[Layer 7: Artifact Serializer (IyiMod)]
       |
       v
[Layer 8: Command Driver + Main Entrypoint]
```

Wiring across the Crystal/iyi language boundary can only happen where a clean
process or file boundary exists. An in-memory boundary (e.g. passing AST nodes
from pure iyi Lexer/Parser into Crystal's Semantic Analyzer) requires either
full serialization or an FFI bridge that is more complex than completing the
port. Therefore, the compilation pipeline must be assembled entirely within iyi,
while standalone tools (`mod`, `format`, `check --parse-only`) are wired via
CLI companion dispatch.

### The Heap Boundary: In-Process Replacement vs. Self-Hosted Pipeline

The question that determines whether Stage One is close or far is whether
ported components can be wired in-process into Crystal's compiler pipeline
(`src/compiler/iyi.cr`), or whether Stage One requires assembling the full
pipeline in pure iyi (`src/compiler/iyi.iyi`).

`STAGE_ONE.md` originally identified the heap boundary as the primary blocker.
With the prelude now compiling and linking on iyi's own raise runtime
(`__crystal_raise`, `__crystal_personality`, `__crystal_get_exception` in
commit `a509d59a7`), we verified whether this boundary still holds.

**The heap boundary is still 100% load-bearing.** In fact, the arrival of iyi's
own raise runtime confirms that pure-iyi is a sovereign, distinct runtime that
cannot be linked in-process into Crystal.

Four concrete technical barriers prevent in-process component replacement:

1. **Incompatible Memory Allocators:**
   Crystal runs on Boehm GC (`libgc.1.dylib`). Every Crystal object allocation
   calls `GC_malloc`, and the collector traces references across Boehm pages.
   In contrast, pure iyi compiles with `IyiHeap` (`src/iyi/prelude.iyi`), which
   allocates via direct `mmap` into custom size-class arenas with thread-local
   caches. Boehm GC does not scan `IyiHeap` memory, and `IyiHeap` does not scan
   Crystal stack frames or Boehm heap objects. If an `ast.iyi` node were passed
   to Crystal's semantic analyzer, any Crystal object pointed to only from
   `IyiHeap` would be collected as garbage, causing use-after-free corruption.

2. **Binary Symbol Collisions:**
   Both runtimes export identical C ABI symbol names. As verified by `nm -gU`:
   * `.build/iyi` (Crystal) defines `___crystal_malloc64`, `___crystal_malloc_atomic64`,
     `___crystal_realloc64`, `___crystal_personality`, `___crystal_raise`, and
     `___crystal_get_exception`.
   * Any object file compiled from `src/compiler/**/*.iyi` defines `___crystal_malloc64`,
     `___crystal_malloc_atomic64`, `___crystal_personality`, `___crystal_raise`, and
     `_IyiHeap::*`.
   Attempting to link a pure-iyi `.o` file into `.build/iyi` fails immediately
   at link time with duplicate symbol errors.

3. **Incompatible Object Layout and VTables:**
   Crystal's `ASTNode` is laid out by Crystal's compiler with Crystal type IDs,
   vtable pointers, and instance variable offsets. Pure iyi's `ASTNode` is laid out
   by `codegen.iyi` with `IyiHeap` headers and vtables emitted by the ported backend.
   A Crystal method cannot dispatch virtual calls on an `ast.iyi` node.

4. **The Raise Runtime Does Not Unify Heaps:**
   Implementing `__crystal_raise` in pure iyi over Itanium DWARF unwinding solved
   Hole 3 for pure-iyi programs (allowing all 17 prelude files to link into binaries
   that need only `libSystem`). It did not build an FFI bridge to Crystal. Both
   Crystal and iyi now implement personality routines that handle their respective
   exception hierarchies, making linking them into the same binary even more
   structurally impossible.

**Conclusion:** Stage One cannot be achieved by incrementally swapping classes
inside Crystal's `src/compiler/iyi.cr`. Stage One is achieved when the bootstrap
compiler (`bin/iyi`) compiles the pure-iyi pipeline (`src/compiler/iyi.iyi`) into
an executable compiler (`.build/iyi-stage1`). CLI companion dispatch (`--selfhost`)
remains the only sound mechanism for running ported components from the bootstrap
compiler today.

## 5. The First Wired Component: `iyi mod dump --selfhost`

`artifact/iyimod.iyi` was selected as the first component to wire into the
shipped compiler because:

1. **Complete specification coverage:** All twenty section types in SPEC.md
   Part IV are fully implemented.
2. **Proven 100% binary parity:** All 16 modules in the corpus (80,398 bytes)
   produce byte-identical `.iyimod` files and byte-identical dumps.
3. **Clean boundary:** The tool operates on files on disk and emits formatted
   text or JSON to standard output. There is no in-memory runtime or GC
   impedance mismatch between Crystal and iyi.
4. **Direct user-facing command:** SPEC.md IV.1 specifies `iyi mod dump FILE`
   as the user-facing inspection tool.

### Implementation

1. **Companion tool (`src/compiler/tools/mod.iyi`):**
   Pure iyi tool that imports `compiler/artifact/iyimod` and implements `dump`,
   `declarations`, and `json` commands.
2. **Compiler CLI wiring (`src/compiler/iyi/command/mod.cr`):**
   `Iyi::Command#mod` and `mod_dump` accept `--selfhost` (either before or after
   the subcommand). When present, `run_selfhost_mod_dump` locates `iyi-mod`
   beside the compiler binary, in `.build/iyi-mod`, or via `IYI_MOD_BIN`, and
   delegates execution.
3. **Build system (`Makefile`):**
   Added `.PHONY: iyi-mod` target compiling `$(O)/iyi-mod$(EXE)` using
   `$(O)/iyi build src/compiler/tools/mod.iyi`.
4. **Differential wiring gate (`bench/selfhost_mod_wiring_exercise.sh`):**
   Verifies that:
   * `iyi mod dump "$file"` equals `iyi mod dump --selfhost "$file"`.
   * `iyi mod dump --declarations "$file"` equals `iyi mod dump --declarations --selfhost "$file"`.
   * Prefix flag syntax `iyi mod --selfhost dump "$file"` works identically.
   * Corrupted artifacts are refused by both with identical verdicts.
   * Four guarded mutation proofs verify that defects in the tool, the
     formatter, the CLI routing, and the format validator are caught.

### Measured Parity Summary

Running `bash bench/selfhost_mod_wiring_exercise.sh` confirms:

```
Dump parity summary: 16/16 modules match byte-for-byte
Declarations parity summary: 16/16 modules match byte-for-byte
Prefix flag summary: 16/16 modules match
Refusal parity: 5/5 corrupted artifact scenarios properly refused by both
Mutation proofs: 4/4 guarded mutations caught and reverted
Parity summary: 16/16 modules match byte-for-byte across dump and declarations (100% parity)
ALL SELFHOST MOD WIRING CHECKS PASSED SUCCESSFULLY!
```

## 6. The Second Wired Component: `iyi tool format --selfhost`

`tools/formatter.iyi` was selected as the second component to wire into the
shipped compiler because:

1. **Clean process boundary:** The formatter is a pure text-to-text transform
   taking source code in and emitting formatted code out. Like the artifact
   inspector, it avoids any in-memory object passing or GC runtime conflict
   between Crystal and iyi.
2. **Proven 100% byte-for-byte parity:** All 35 files in the formatter corpus
   (106,026 bytes) produce byte-identical formatted code between the Crystal
   frontend and the pure iyi implementation.
3. **Direct user-facing command:** `iyi tool format [options] [files]` is an
   active user-facing CLI command. Wiring the self-hosted formatter allows users
   and CI to exercise the pure iyi formatter directly on real codebases today.
4. **Preserved default behavior:** Default invocation (`iyi tool format`) is
   completely untouched, while `--selfhost` (or prefix `tool --selfhost format`)
   routes execution to the companion tool.

### Implementation

1. **Companion tool (`src/compiler/tools/format.iyi`):**
   Pure iyi tool that imports `compiler/tools/formatter` and formats source
   from file paths or standard input.
2. **Compiler CLI wiring (`src/compiler/iyi/command/format.cr` and `command.cr`):**
   `Iyi::Command#format` and `FormatCommand` accept `--selfhost` (either before or
   after the `format` subcommand). When present, `run_selfhost_format` locates
   `iyi-format` beside the compiler binary, in `.build/iyi-format`, or via
   `IYI_FORMAT_BIN`, and delegates execution.
3. **Build system (`Makefile`):**
   Added `.PHONY: iyi-format` target compiling `$(O)/iyi-format$(EXE)` using
   `$(O)/iyi build src/compiler/tools/format.iyi`.
4. **Differential wiring gate (`bench/selfhost_format_wiring_exercise.sh`):**
   Verifies that:
   * `iyi tool format - < file` equals `iyi tool format --selfhost - < file`.
   * `iyi tool format file` in-place equals `iyi tool format --selfhost file`.
   * Prefix flag syntax `iyi tool --selfhost format` works identically.
   * Check mode (`--check`) parity on both clean files (exit 0) and unformatted files (exit 1).
   * Syntax error refusal parity on malformed source files (exit 1).
   * Five guarded mutation proofs verify that defects in the companion tool,
     the STDIN handler, the delegation output capture, the prefix flag routing,
     and the check mode status code are caught.

### Measured Parity Summary

Running `bash bench/selfhost_format_wiring_exercise.sh` confirms:

```
STDIN parity summary: 35/35 files match byte-for-byte
In-place parity summary: 35/35 files match byte-for-byte
Prefix flag summary: 35/35 files match
clean check parity: 35/35 files pass on both paths
unformatted check refusal: both paths detect changes (rc=1)
syntax error properly refused by both (rc=1)
Mutation proofs: 5/5 guarded mutations caught and reverted
Parity summary: 35/35 files match byte-for-byte across stdin, in-place, and prefix flags (100% parity)
ALL SELFHOST FORMAT WIRING CHECKS PASSED SUCCESSFULLY!
```

## 7. The Third Wired Component: `iyi check --parse-only --selfhost`

`syntax/parser.iyi` and `syntax/lexer.iyi` were selected as the third component to wire into the
shipped compiler because:

1. **Clean process boundary:** Front-end syntax checking is a file-in or text-in, verdict-out
   transform that validates syntax without mutating disk state or executing codegen. It avoids
   any in-memory runtime or Boehm GC conflict between Crystal and pure iyi.
2. **Proven 100% parity on real corpus:** All 68 files in the test corpus (the 24 parser syntax
   fixtures and the 44 sample programs in the samples tree) produce identical verdicts and
   clean exits (exit code 0, empty output) across files, STDIN, and flag ordering.
3. **Identical error text on malformed input:** Syntax errors on malformed input exit with
   status 1 and output byte-identical error messages between the Crystal and self-hosted paths.
4. **Direct user-facing command:** `iyi check --parse-only [--selfhost] [files...]` extends the
   shipped `check` command so users and CI can exercise the pure iyi front end on real codebases.
5. **Preserved default behavior:** Default invocation (`iyi check`) and standard syntax checking
   (`iyi check --parse-only`) are completely untouched, while `--selfhost` routes execution to
   the companion tool `iyi-parse`.

### Implementation

1. **Companion tool (`src/compiler/tools/parse.iyi`):**
   Pure iyi tool that imports `compiler/syntax/parser` and parses source files or standard input.
2. **Compiler CLI wiring (`src/compiler/iyi/command/check.cr`):**
   `Iyi::Command#check` accepts `--parse-only` and `--selfhost`. When `--selfhost` is combined
   with `--parse-only`, `run_selfhost_parse` locates `iyi-parse` beside the compiler binary,
   in `.build/iyi-parse`, or via `IYI_PARSE_BIN`, and delegates execution.
3. **Build system (`Makefile`):**
   Added `.PHONY: iyi-parse` target compiling `$(O)/iyi-parse$(EXE)` using
   `$(O)/iyi build -o $@ src/compiler/tools/parse.iyi`.
4. **Differential wiring gate (`bench/selfhost_parser_wiring_exercise.sh`):**
   Verifies that:
   * `iyi check --parse-only file` equals `iyi check --parse-only --selfhost file` across all 68 files.
   * `iyi check --parse-only - < file` equals `iyi check --parse-only --selfhost - < file`.
   * Flag ordering `iyi check --selfhost --parse-only` works identically.
   * Syntax error refusal parity on malformed source files with identical exit code (rc=1) and error text.
   * Five guarded mutation proofs verify that defects in the companion tool, STDIN parsing,
     tool discovery, flag routing, and status code propagation are caught.

### Measured Parity Summary

Running `bash bench/selfhost_parser_wiring_exercise.sh` confirms:

```
Parity summary: 68/68 files match byte-for-byte across files, stdin, and flag ordering (100% parity)
Refusal summary: 5/5 malformed scenarios refused with identical error text and status (rc=1)
Mutation summary: 5/5 guarded wiring mutations caught and reverted
ALL SELFHOST PARSER WIRING CHECKS PASSED SUCCESSFULLY!
```

## 8. Observable Proof of Stage One

Stage One will be demonstrably complete when:

1. **Self-hosted entrypoint exists:**
   `src/compiler/iyi.iyi` imports all layers (0 through 8) and implements the
   full compiler pipeline in pure iyi.
2. **Crystal builds Stage One:**
   Running `bin/iyi build -o .build/iyi-stage1 src/compiler/iyi.iyi` exits 0
   and produces an executable compiler binary.
3. **Executable validation:**
   `.build/iyi-stage1 --version` executes, prints the compiler version, and
   does not segfault or panic.
4. **Compilation proof:**
   `.build/iyi-stage1 build -o .build/calc-stage1 samples/iyi/calc.iyi`
   successfully compiles a non-trivial program containing lexing, parsing,
   custom structs, methods, traits, and standard library imports.
5. **Runtime verification:**
   The compiled binary `.build/calc-stage1` runs, passes its tests, and matches
   the behavior of the binary compiled by `bin/iyi`.
6. **Selfhost gate pass:**
   All twenty selfhost exercise scripts pass when invoked with `IYI=.build/iyi-stage1`.
7. **Dependency floor holds:**
   `bash bench/dependency_floor.sh` confirms that binaries produced by Stage One
   continue to link only the platform libc (`libSystem.B.dylib` on darwin).
