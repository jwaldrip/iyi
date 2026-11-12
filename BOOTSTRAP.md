# The bootstrap contract

What it takes for iyi to compile itself, what each stage has to prove before the next one starts, and what is still linked when it is done.

Every figure here was measured at commit 9a2a08173, with the command written beside it. A gate verdict is the exit code that the baseline run recorded in `/tmp/iyi-b-baseline/matrix.txt` at that commit. `bench/doc_numbers.py` does not read this file, and no figure here depends on it.

## Where this stands

Two measurements made after the baseline matrix above, on the branch named in each:

- **Typed parity is 26 of 25,436 oracle expression nodes (0.10 percent).** Measured on `selfhost/s0-typed-parity` (remote head `bfcd869e5`, "selfhost: line A's corpora through line B's lexer, parser and declaration tools (S0)"). The gate is `bench/selfhost_typed_parity_exercise.sh` on that branch. The 26 is the sum of the matched counts in its committed floor file `bench/selfhost_typed_parity.floor` (`git show FETCH_HEAD:bench/selfhost_typed_parity.floor`, 228 entries). The 25,436 is the oracle's node total, which the gate prints when it runs; this document quotes that figure from the measurement made for the S0 branch and did not re-run the gate. So the port types 26 of 25,436 nodes the Crystal oracle types, identically, on that corpus.
- **The parser gate proves parity on syntax fixtures only.** `bench/selfhost_parser_exercise.sh` compares the normalised trees of its syntax fixtures, and the dump tools do not name module headers, imports or annotations. So a real program, which begins with a module header or an import, differs from the Crystal parser at its first node. The gate's green verdict (exit 0 at the baseline) says nothing about those first nodes.

Measured at 9a2a08173:

- Crystal in `src/compiler`: 138,424 lines in 201 files. `find src/compiler -name '*.cr' -print0 | xargs -0 cat | wc -l`
- iyi in `src/compiler`: 41,938 lines in 52 files. `find src/compiler -name '*.iyi' -print0 | xargs -0 cat | wc -l`
- Prelude in `src/iyi`: 28,880 lines in 20 files. `cat src/iyi/*.iyi | wc -l`
- Selfhost gates: 23. `ls bench/selfhost_*_exercise.sh | wc -l`
- Stage-one entry point: `src/compiler/stage1.iyi`, 37 lines. `wc -l src/compiler/stage1.iyi`

The port, component by component. Paths are under `src/compiler/`. Each line count is `wc -l` over the files in that row, and the rows add to 41,938, the iyi total above. The verdict is the exit code the gate recorded in the baseline matrix.

| Component | Files | Lines | Gate | Verdict |
|---|---|---:|---|---|
| Foundation | `foundation/*.iyi` (4 files) | 133 | none of its own; named by the lexer, AST and bind gates | no gate targets it alone |
| Lexer and token | `syntax/lexer.iyi`, `syntax/token.iyi` | 3,468 | `selfhost_lexer_exercise` | `exit=0` |
| AST, visitor, transformer | `syntax/ast.iyi`, `syntax/visitor.iyi`, `syntax/transformer.iyi` | 7,220 | `selfhost_ast_exercise` | `exit=0` |
| Parser | `syntax/parser.iyi` | 5,194 | `selfhost_parser_exercise`, `selfhost_parser_wiring_exercise` | `exit=0`, `exit=1` |
| Normalizer | `semantic/normalizer.iyi` | 701 | `selfhost_normalizer_exercise` | `exit=1` |
| Semantic passes | `semantic/top_level.iyi`, `semantic/main_visitor.iyi`, `semantic/recursive_struct_checker.iyi` | 3,258 | `selfhost_semantic_exercise` | `exit=0` |
| Types | `types.iyi`, `types/*.iyi` (7 files) | 2,086 | `selfhost_types_exercise` | `exit=0` |
| Macro engine | `macros/*.iyi` (5 files) | 1,607 | `selfhost_macros_exercise` | `exit=0` |
| LLVM bindings | `llvm.iyi`, `llvm/*.iyi` (10 files) | 2,359 | `selfhost_llvm_exercise` | `exit=1` |
| Platform | `platform/*.iyi` (3 files) | 696 | `selfhost_platform_exercise` | `exit=0` |
| Code generation | `codegen/codegen.iyi` | 4,801 | `selfhost_codegen_exercise`, `selfhost_ir_valid_exercise` | `exit=1`, `exit=1` |
| Artifact format | `artifact/iyimod.iyi` | 2,677 | `selfhost_iyimod_exercise`, `selfhost_mod_wiring_exercise` | `exit=1`, `exit=1` |
| Command driver | `command/driver.iyi` | 2,152 | `selfhost_command_exercise` | `exit=1` |
| Daemon | `command/daemon.iyi` | 715 | `selfhost_daemon_exercise` | `exit=1` |
| Formatter | `tools/formatter.iyi` | 2,487 | `selfhost_formatter_exercise`, `selfhost_format_wiring_exercise` | `exit=1`, `exit=1` |
| Bind tool | `tools/bind.iyi` | 1,208 | `selfhost_bind_exercise` | `exit=1` |
| Companion tools | `tools/format.iyi` (33), `tools/mod.iyi` (39), `tools/parse.iyi` (41), `tools/compile.iyi` (108) | 221 | `selfhost_format_wiring_exercise`, `selfhost_mod_wiring_exercise`, `selfhost_parser_wiring_exercise`, `selfhost_compile_exercise` | see the rows above |
| Loader | `loader.iyi` | 343 | `selfhost_compile_exercise` | `exit=1` |
| Pipeline | `compiler.iyi` | 575 | `selfhost_compile_exercise` | `exit=1` |
| Stage-one entry | `stage1.iyi` | 37 | `selfhost_stage_one_exercise` | `exit=1` |

The prelude in `src/iyi` is gated by `selfhost_prelude_exercise` and `selfhost_prelude_whole_exercise`. Their verdicts are `exit=1` and `exit=1`. STAGE_TWO.md section 4 records what each one measures.

The baseline gate results are below, and the output lines each gate prints for its own summary are in STAGE_TWO.md (section 3).

Head at the baseline: 9a2a08173, a clean checkout (`dirty=0`). Verdicts are the exit codes in `/tmp/iyi-b-baseline/matrix.txt`, which ends in `DONE`. The cause column quotes one line of the gate's own log.

| Gate | Baseline verdict | Gate's own cause (verbatim) |
|---|---|---|
| `selfhost_ast_exercise` | `exit=0` | green |
| `selfhost_bind_exercise` | `exit=1` | `FAILED: the comparison still passed with the mutation applied` |
| `selfhost_codegen_exercise` | `exit=1` | `FAIL: bench/fixtures/cg_closures.iyi diverged from front end:` |
| `selfhost_command_exercise` | `exit=1` | `== SELFHOST COMMAND DRIVER CHECKS FAILED` |
| `selfhost_compile_exercise` | `exit=1` | `FAIL: mutation was not caught: wrong resolver resolution order` |
| `selfhost_daemon_exercise` | `exit=1` | `Error: k_str.to_unsafe answers Pointer(UInt8), raw memory the compiler does not check, and bench/selfhost_daemon_exercise.iyi is not marked unsafe.` |
| `selfhost_format_wiring_exercise` | `exit=1` | `Error: @buffer is a Pointer(UInt8), raw memory the compiler does not check, and compiler/tools/formatter is not marked unsafe (10 more places in this module do the same).` |
| `selfhost_formatter_exercise` | `exit=1` | `Error: @buffer is a Pointer(UInt8), raw memory the compiler does not check, and compiler/tools/formatter is not marked unsafe (10 more places in this module do the same).` |
| `selfhost_ir_valid_exercise` | `exit=1` | `array.iyi pass fail: Terminator found in the middle of a basic block! REGRESSION` |
| `selfhost_iyimod_exercise` | `exit=1` | `Error: _.initialize answers Pointer(UInt8), raw memory the compiler does not check, and compiler/artifact/iyimod is not marked unsafe (44 more places in this module do the same).` |
| `selfhost_lexer_exercise` | `exit=0` | green |
| `selfhost_llvm_exercise` | `exit=1` | `Error: ctx.to_unsafe answers Pointer(Void), raw memory the compiler does not check, and bench/selfhost_llvm_exercise.iyi is not marked unsafe (8 more places in this module do the same).` |
| `selfhost_macros_exercise` | `exit=0` | green |
| `selfhost_mod_wiring_exercise` | `exit=1` | `Error: _.initialize answers Pointer(UInt8), raw memory the compiler does not check, and compiler/artifact/iyimod is not marked unsafe (44 more places in this module do the same).` |
| `selfhost_normalizer_exercise` | `exit=1` | `bench/fixtures/norm_defer.iyi: NORMALISED TREES DIFFER` |
| `selfhost_parser_exercise` | `exit=0` | green |
| `selfhost_parser_wiring_exercise` | `exit=1` | `REFUSAL TEXT MISMATCH for '(1 + 2':` |
| `selfhost_platform_exercise` | `exit=0` | green |
| `selfhost_prelude_exercise` | `exit=1` | `array.iyi 934 link codegen REGRESSION` |
| `selfhost_prelude_whole_exercise` | `exit=1` | `prelude (whole) codegen none REGRESSION` |
| `selfhost_semantic_exercise` | `exit=0` | green |
| `selfhost_stage_one_exercise` | `exit=1` | `Error: lib LibC declares C functions the compiler does not check, and compiler/stage1 is not marked unsafe (1 more place in this module does the same).` |
| `selfhost_types_exercise` | `exit=0` | green |

### What is not in iyi

- **The Crystal semantic analyzer is still the only complete one.** `src/compiler/iyi/semantic/*.cr` holds 48 files and 36,838 lines (`cat src/compiler/iyi/semantic/*.cr | wc -l`). The three iyi passes above cover part of it.
- **The macro engine has no TypeNode inspection, no external macro run and no semantic hooks.** `grep -rn TypeNode src/compiler/macros/*.iyi | wc -l` prints 0. `grep -rn 'macro run\|inherited\|included' src/compiler/macros/*.iyi | wc -l` prints 0.
- **Code generation never reads the main visitor it is given.** The class takes one (`property main_visitor` at `codegen.iyi` line 349, and the constructor parameter at line 386). `grep -rn '\.main_visitor' src/compiler --include='*.iyi' | wc -l` prints 0.
- **The stage-one entry point does not compile at this commit.** `bin/iyi build -o .build/iyi-stage1 src/compiler/stage1.iyi` exits 1. STAGE_ONE.md section 5 has the output.
- **No minimal compiler prelude exists.** `src/compiler/prelude.iyi` is absent (`ls src/compiler/prelude.iyi`).

## The stages

Stage zero is the contract, not a build. It is the set of statements a later stage is measured against, so that "it bootstrapped" is a checkable claim rather than a feeling.

**Stage 0, the contract.** No compiler is built. What has to be true:

1. Every iyi file under `src/compiler` compiles with the current compiler and is exercised by a gate that carries a failure proof. Three files are named by no bench script at this commit: `src/compiler/llvm/lib_llvm.iyi`, `src/compiler/types/filtering.iyi`, `src/compiler/types/restrictions.iyi`. The check is `for f in $(find src/compiler -name '*.iyi'); do m=${f#src/}; m=${m%.iyi}; b=$(basename "$f" .iyi); grep -rqF -e "$f" -e "$m" -e "/$b" bench/*.sh bench/*.iyi || echo "$f"; done`. A file exercised only through an import from another gated file is not counted here.
2. A stage-one compiler is built *by Crystal* from iyi sources. Its output is the thing under test, never its own source. The gate is `selfhost_stage_one_exercise`, verdict `exit=1`.
3. A stage-two compiler is built *by stage one* from the same sources. Not reached: there is no stage-one binary to build it (STAGE_ONE.md section 5).
4. Stage two is byte-identical to a stage three built by stage two. Not reached, for the same reason.
5. The reproduction is measured with `SOURCE_DATE_EPOCH` pinned and the artifact paths normalised, because otherwise the comparison proves the filesystem rather than the compiler. No gate pins it yet.

**Stage 1.** Crystal compiles iyi sources into a compiler, `src/compiler/stage1.iyi` and the modules it imports. The entry point exists. Whether it builds is the verdict above, and what it does once built is STAGE_ONE.md section 5.

**Stage 2.** Stage one compiles the same sources. The first moment iyi is compiled by an iyi binary. Not reached.

**Stage 3.** Stage two compiles the same sources. `cmp` stage two against stage three. Equal is the pass. Not reached.

## What is still linked

This is the part worth being plain about, because "self-hosted" is often heard as "dependency free", and it is not the same claim.

Measured on the Crystal-built compiler at this commit, which is what `bin/iyi` runs (`bin/iyi` execs `.build/iyi`):

```
$ otool -L .build/iyi
	/opt/homebrew/opt/llvm/lib/libLLVM.dylib
	/usr/lib/libSystem.B.dylib
```

The iyi bindings say why LLVM is there. `grep -n '@\[Link' src/compiler/llvm/lib_llvm.iyi` prints line 18, `@[Link("stdc++")]`, and line 20, `@[Link(ldflags: {{ llvm_ldflags }})]`. So a self-hosted compiler links libLLVM and libstdc++ through those bindings. Writing the bindings in iyi changes who calls LLVM, not whether LLVM is there.

LLVM leaves the iyi-written compiler one target at a time, as each target's native back end lands. Until the last target has one, the bindings stay. Removing them is part of the native back end work, and nothing here assumes that work is done.

The platform libc remains. Every program built for a supported target links it, and the dependency floor gate is where that is measured.

The collector is a separate question. Earlier builds of this checkout also linked `libgc` (`otool -L` on the binary from 14 September printed `libgc.1.dylib`). The build at this commit does not. The prelude links libgc only in a build with `-Dgc_boehm` (`src/iyi/prelude.iyi`, the `{% if flag?(:gc_boehm) %}` block at line 1585, whose comment at line 1577 says so).

So the honest end state of this work is a compiler that needs libc and, until each native back end lands, LLVM.

## What would make this contract false

Each of these is a way the claim could read as satisfied while being wrong, so each one is a gate or it is not being checked:

- A stage-two build that reuses stage one's artifacts rather than recompiling. The reproduction must start from a clean artifact directory.
- Comparing stage one against stage two and calling it a fixed point. It is not; they had different producers.
- A byte comparison that passes because both binaries embed the same timestamp path rather than the same code.
- A file under `src/compiler` that no gate names. The coverage command in stage 0 finds these.
