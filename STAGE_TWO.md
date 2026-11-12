# The Stage Two Contract

What stage two requires, the dependency order of the components, the architectural holes that separate this tree from a self-hosted compiler, and the observable that ends the objective.

Every figure here was measured at commit 9a2a08173, with the command written beside it. A gate verdict is the exit code recorded in the baseline run at `/tmp/iyi-b-baseline/matrix.txt`. Section 6 is the goal. BOOTSTRAP.md has the port table, and STAGE_ONE.md has the stage-one contract.

## 1. Stages and the heap boundary

`BOOTSTRAP.md` defines four stages, and STAGE_ONE.md section 1 says what each means in this tree. Stage two is where the iyi compiler is built by stage one and then compiles itself. Stage three is the fixed-point check, `cmp` of stage two against stage three.

### The heap boundary

Crystal's compiler allocates AST nodes, symbols and types on the Boehm collector's heap. The iyi front end allocates its nodes on iyi's runtime heap. Passing AST nodes from the iyi parser into Crystal's semantic analyzer in one process would need both collectors to manage intertwined data, so the cutover has to happen at a whole-compiler binary boundary.

Every component wired so far respects this by running as a companion process:

* `iyi mod dump --selfhost` runs `.build/iyi-mod` (Makefile target `iyi-mod`).
* `iyi tool format --selfhost` runs `.build/iyi-format` (Makefile target `iyi-format`).
* `iyi check --parse-only --selfhost` runs `.build/iyi-parse` (Makefile target `iyi-parse`).
* `.build/iyi-compile` is a standalone tool (Makefile target `iyi-compile`).

## 2. Measured state

* Crystal in `src/compiler`: 138,424 lines in 201 files. `find src/compiler -name '*.cr' -print0 | xargs -0 cat | wc -l`
* iyi in `src/compiler`: 41,938 lines in 52 files. `find src/compiler -name '*.iyi' -print0 | xargs -0 cat | wc -l`
* Crystal under `src/compiler/iyi/`, which the stage-two goal removes: 196 files and 138,071 lines. `find src/compiler/iyi -name '*.cr' -print0 | xargs -0 cat | wc -l`
* `src/llvm`, which the stage-two goal also removes: 36 entries. `ls src/llvm | wc -l`
* Prelude in `src/iyi`: 28,880 lines in 20 files. `cat src/iyi/*.iyi | wc -l`

The port, component by component, is in BOOTSTRAP.md. Its rows add to the iyi total above.

## 3. The selfhost gates

There are 23 selfhost gates (`ls bench/selfhost_*_exercise.sh | wc -l`). Each row gives the baseline exit code and the summary line that gate printed in its own log.

| Gate | Exit | Summary line from its log |
|---|---|---|
| `selfhost_ast_exercise` | pending | pending |
| `selfhost_bind_exercise` | pending | pending |
| `selfhost_codegen_exercise` | pending | pending |
| `selfhost_command_exercise` | pending | pending |
| `selfhost_compile_exercise` | pending | pending |
| `selfhost_daemon_exercise` | pending | pending |
| `selfhost_format_wiring_exercise` | pending | pending |
| `selfhost_formatter_exercise` | pending | pending |
| `selfhost_ir_valid_exercise` | pending | pending |
| `selfhost_iyimod_exercise` | pending | pending |
| `selfhost_lexer_exercise` | pending | pending |
| `selfhost_llvm_exercise` | pending | pending |
| `selfhost_macros_exercise` | pending | pending |
| `selfhost_mod_wiring_exercise` | pending | pending |
| `selfhost_normalizer_exercise` | pending | pending |
| `selfhost_parser_exercise` | pending | pending |
| `selfhost_parser_wiring_exercise` | pending | pending |
| `selfhost_platform_exercise` | pending | pending |
| `selfhost_prelude_exercise` | pending | pending |
| `selfhost_prelude_whole_exercise` | pending | pending |
| `selfhost_semantic_exercise` | pending | pending |
| `selfhost_stage_one_exercise` | pending | pending |
| `selfhost_types_exercise` | pending | pending |

## 4. Holes

### Hole 1: the pipeline orchestrator

* **Status:** pending (`selfhost_compile_exercise`).
* **Evidence:** `src/compiler/compiler.iyi` (575 lines) orchestrates resolve, parse, normalise, semantic, code generation, object emission and linking. It calls `append_entry_point` (line 137) and `Compiler.append_raise_runtime` (line 139, when the program does not define `__crystal_raise`). `src/compiler/tools/compile.iyi` (108 lines) is the command-line wrapper over it. The gate's summary: pending

### Hole 2: the module resolver

* **Status:** pending, the same gate.
* **Evidence:** `src/compiler/loader.iyi` (343 lines) resolves imports against relative directories, header roots and `IYI_PATH`, detects cycles, and orders modules topologically. The gate runs `bench/fixtures/compile_multi_import.iyi`, `compile_diamond.iyi` and `compile_missing_import.iyi`, among others (`ls bench/fixtures/compile_*.iyi` lists 17 fixtures).

### Hole 3: the prelude barrier, and why it is not closed

* **Phase gate.** `bench/selfhost_prelude_exercise.sh` records the highest phase each file in `src/iyi` reaches. Its verdict is pending, and its summary is pending. Committed floors cover 17 files. `chaos.iyi`, `chaos_points.iyi` and `testing.iyi` have no floor and default to `none` (the `*)` case in the script), so the gate cannot catch a regression in them. The phase table below is the gate's own output:

pending (the phase table is the gate's own output, added with the verdict table)

* **Whole-prelude gate.** `bench/selfhost_prelude_whole_exercise.sh` compiles the prelude as one unit rather than file by file. Verdict pending. Summary: pending

* **IR validity.** `bench/selfhost_ir_valid_exercise.sh` checks that the IR the backend emits verifies, not only that it is accepted by object emission. Its verdict is pending. Its summary is pending. Two files are recorded as known failures, `concurrency.iyi` and `prelude.iyi`, and `prelude.iyi` inherits the same defect, as the gate's comment says, because it requires `concurrency.iyi`. The verifier message for `concurrency.iyi`, from the log, is: pending. Object emission accepting a module does not make the module valid, and invalid IR is likely to surface as a miscompile before it surfaces as an error [INFERENCE].

* **The raise runtime is being retired.** The port carries a native unwinder, `Compiler.append_raise_runtime` (`src/compiler/compiler.iyi`, line 424), which declares the platform unwinder's entry points (`_Unwind_RaiseException` and five others, lines 438 to 443) and implements `__crystal_raise`, `__crystal_personality` and `__crystal_get_exception` on the Itanium C++ exception ABI: the `_Unwind_*` entry points, and the language-specific call-site tables its personality routine parses. It is being retired because iyi refuses `rescue` and `ensure` in iyi files (SPEC.md, the paragraph that begins "Because errors are values returned early", lines 2409 to 2415). A runtime that exists to implement `rescue` has no caller once `rescue` is refused. Nothing in the tree retires it yet.

* **What the raise gate proves, and what it does not.** `bench/fixtures/compile_raise.iyi` defines its own `__crystal_get_exception` (line 56), `__crystal_raise` (line 62) and `__crystal_personality` (line 80). The three mutations labelled "corrupt runtime" in `bench/selfhost_compile_exercise.sh` (lines 326 to 345) patch that fixture. They never touch `Compiler.append_raise_runtime`, so they show that the fixture's own runtime is checked, not the injected one. The one mutation that reaches the injected runtime's use is "pipeline supplies raise runtime when missing" (lines 347 to 352). It comments out the call at `compiler.iyi` line 139, and the probe is `bench/fixtures/compile_implicit_raise.iyi`. `src/iyi/prelude.iyi` no longer defines `__crystal_raise` (`grep -n '__crystal_raise' src/iyi/prelude.iyi` prints nothing), so a program that requires the prelude takes the injected path. Whether such a program raises and rescues correctly was not measured at this commit.

### Hole 4: macros in semantic traversal

* **Status:** pending (`selfhost_semantic_exercise`).
* **Evidence:** `src/compiler/semantic/main_visitor.iyi` imports `MacroEngine` (line 8), visits `Macro` nodes (line 80) and constructs a `MacroEngine` (line 95). Whether macros expand during traversal is what the semantic gate tests. The gate's summary: pending

### Hole 5: top-level statements in code generation

* **Status:** pending, the same gate.
* **Evidence:** `append_entry_point` (`src/compiler/codegen/codegen.iyi`, line 4349) wraps top-level statements into `__crystal_main` and `main`. It is called from `codegen.iyi` (line 4422) and from `compiler.iyi` (line 137), so the single-file path and the multi-file pipeline share one wrapper. `bench/fixtures/compile_top_level.iyi` and `compile_no_top_level.iyi` are the probes.

### Hole 6: the bootstrap chicken-and-egg

* **Status:** Structural. The iyi compiler source is 41,938 lines (BOOTSTRAP.md, the command there), and it has to be compiled by an existing compiler. Crystal builds `.build/iyi` today, which links libLLVM and libSystem only (`otool -L .build/iyi`). The first compiler binary that does not depend on the Crystal-built one can only come from stage one building `src/compiler/stage1.iyi` into an executable. At this commit that build exits 1, because the compiler refuses the entry point's `lib LibC` under its own `@[Unsafe]` rule (STAGE_ONE.md section 5).

## 5. Order of operations, with status

The steps are in dependency order. Each one says what is measured.

1. **End-to-end program compiler.** `.build/iyi-compile` is built from `src/compiler/tools/compile.iyi` and the gate is pending. Done as far as the gate proves.
2. **Semantic analysis as a companion tool.** Not started. `src/compiler/tools/` holds `bind.iyi`, `compile.iyi`, `format.iyi`, `formatter.iyi`, `mod.iyi` and `parse.iyi` (`ls src/compiler/tools`), and no check tool. `iyi check --parse-only [--selfhost]` is the only selfhost mode (`src/compiler/iyi/command/check.cr`, the usage line).
3. **Multi-file loader.** Done as far as the gate proves, with `src/compiler/loader.iyi` (343 lines) and pending.
4. **Code generation primitives: string literals, heap layouts, generics.** Partly done. The codegen gate is pending. The gaps are the IR validity gap in hole 3 and STAGE_ONE.md section 3, layer 6.
5. **Minimal compiler prelude.** Not started. `src/compiler/prelude.iyi` does not exist (`ls src/compiler/prelude.iyi` fails).
6. **Top-level assembly.** Partly. `src/compiler/stage1.iyi` (37 lines) is the entry point. It does not compile at this commit, so no assembled binary exists (STAGE_ONE.md section 5).
7. **Stage one cutover and removal of the collector.** Not started. `bin/iyi` still execs `.build/iyi`, which Crystal builds (`bin/iyi`, lines 16 and 18).

## 6. The goal, observably

This section is the specification's section 0, which replaces the earlier criterion list. It is the observable goal.

On each compiler host (aarch64-darwin, x86_64-linux-gnu, aarch64-linux-gnu, x86_64-windows), from a clean checkout:

1. `stage1` (the iyi-written compiler, built once by the Crystal-hosted compiler) builds `stage2` from `src/compiler/**/*.iyi`; `stage2` builds `stage3`; `cmp stage2 stage3` exits 0, and so do their debug companions.
2. `stage2` links only the platform's own contract: `otool -L` shows `/usr/lib/libSystem.B.dylib` alone on darwin; `readelf -d` shows no `NEEDED` and `readelf -l` no `INTERP` on Linux; `dumpbin /dependents` shows `kernel32.dll` (plus `advapi32`, `ws2_32`, `crypt32` only where std modules the compiler uses need them) on Windows. `nm stage2 | grep -c LLVM` is 0.
3. Both builds ran with a `PATH` whose `cc clang gcc ld ld64 ld.lld lld mold link.exe lld-link wasm-ld codesign dsymutil llc llvm-*` are tripwires that log and exit 97; the tripwire log is empty.
4. `stage2` builds every program in the sample, prelude and std corpora for all five targets (aarch64-darwin, x86_64-linux-gnu, aarch64-linux-gnu, x86_64-windows, wasm32-wasi); each program, run on its target's runner, matches the same program built by the Crystal-hosted compiler through LLVM in exit status, stdout and stderr.
5. `bench/panics.sh` (including step 9a, named frames through `std/debug`) passes on native outputs.
6. Stale testing (`iyi test --cached`, PR #147) runs on the self-hosted compiler; `src/compiler/iyi/**/*.cr` and `src/llvm/**` are deleted.

Each upstream PR along the way merges green on `iyilang/iyi` CI by itself, with a merge commit.

**Status at 9a2a08173.** None of the six holds yet.

* Items 1 to 3: not met. Stage one does not compile at this commit (STAGE_ONE.md section 5), so there is no stage two, and no `cmp` can run.
* Item 4: not met, because no stage two exists to build the corpora (item 1).
* Item 5: not measured at this commit. `bench/panics.sh` exists (`ls bench/panics.sh`) and was not run against native output.
* Item 6: not met. The Crystal sources under `src/compiler/iyi/` are still present (196 files, `find src/compiler/iyi -name '*.cr' | wc -l`), and `src/llvm` still has 36 entries.
