# The Stage One Contract

What stage one requires, the dependency order of the components, what blocks each one today, and the observable proof of stage one.

Every figure here was measured at commit 9a2a08173, with the command written beside it. A gate verdict is the exit code recorded in the baseline run at `/tmp/iyi-b-baseline/matrix.txt`. BOOTSTRAP.md has the port table and the linking facts, and this file does not repeat them.

## 1. What stage one is

`BOOTSTRAP.md` defines four stages. Here is what each one means in this tree:

* **Stage 0 (the contract):** No self-hosted compiler is built. The contract is the set of statements the later stages are measured against.
* **Stage 1:** Crystal (`bin/iyi`) builds a compiler executable from the iyi sources under `src/compiler`. The entry point is `src/compiler/stage1.iyi`, which runs the ported command driver over `Program.args`. Its output is the thing under test, never its own source.
* **Stage 2:** The stage-one compiler compiles the same sources. This is the first moment iyi is compiled by an iyi binary.
* **Stage 3:** The stage-two compiler compiles the same sources, and `cmp` compares stage two with stage three.

The entry point is `src/compiler/stage1.iyi`. Earlier drafts named a different file for it, and no file of that name is in the tree.

## 2. Measured state

* Crystal in `src/compiler`: 138,424 lines in 201 files. `find src/compiler -name '*.cr' -print0 | xargs -0 cat | wc -l`
* iyi in `src/compiler`: 41,938 lines in 52 files. `find src/compiler -name '*.iyi' -print0 | xargs -0 cat | wc -l`
* The stage-one entry point: 37 lines. `wc -l src/compiler/stage1.iyi`
* The stage-one gate, which builds the entry point with `bin/iyi build -o .build/iyi-stage1 src/compiler/stage1.iyi`: pending
* `bin/iyi` is a shell wrapper that execs `.build/iyi` (`grep -n exec bin/iyi` prints lines 16 and 18).

## 3. Component inventory and blockers

Line counts and gate names are in BOOTSTRAP.md. Each entry gives the gate verdict and what still blocks the component.

**Foundation** (`foundation/*.iyi`). The lexer, AST and bind gates name these files (`grep -rln foundation bench`). No gate targets them alone. Nothing here blocks the other layers.

**Layer 1: lexer and AST** (`syntax/lexer.iyi`, `syntax/token.iyi`, `syntax/ast.iyi`, `syntax/visitor.iyi`, `syntax/transformer.iyi`). Lexer gate pending, AST gate pending. The shipped compiler still lexes with the Crystal lexer in `src/compiler/iyi/syntax/`. The iyi AST is an iyi-heap structure, and the Crystal semantic analyzer consumes Crystal's AST, so the two cannot meet in one process (section 4).

**Layer 2: parser and normalizer** (`syntax/parser.iyi`, `semantic/normalizer.iyi`). Parser gate pending, parser wiring gate pending, normalizer gate pending. The parser builds iyi AST nodes, so it inherits the heap boundary. `iyi check --parse-only --selfhost` routes to it (`src/compiler/iyi/command/check.cr`).

**Layer 3: macros** (`macros/*.iyi`). Gate pending. Not in the port, each checked by grep:
* TypeNode inspection from macros: `grep -rn TypeNode src/compiler/macros/*.iyi | wc -l` prints 0.
* External macro execution (`macro run`) and the semantic hooks `inherited`, `included` and `extended`: `grep -rn 'macro run\|inherited\|included' src/compiler/macros/*.iyi | wc -l` prints 0.

**Layer 4: types and semantic analysis** (`types.iyi`, `types/*.iyi`, `semantic/top_level.iyi`, `semantic/main_visitor.iyi`, `semantic/recursive_struct_checker.iyi`). Types gate pending, semantic gate pending. The complete semantic analyzer is still Crystal: `cat src/compiler/iyi/semantic/*.cr | wc -l` prints 36,838 over 48 files. The iyi passes cover part of it.

**Layer 5: platform and LLVM bindings** (`platform/*.iyi`, `llvm.iyi`, `llvm/*.iyi`). Platform gate pending, LLVM gate pending. The LLVM bindings are consumed by code generation, and they are the reason the iyi-written compiler links LLVM (BOOTSTRAP.md, "What is still linked").

**Layer 6: code generation** (`codegen/codegen.iyi`). Codegen gate pending, IR validity gate pending. Two gaps are measured. Code generation never reads the main visitor it is given: the class takes one (`property main_visitor` at line 349 and the constructor parameter at line 386), and `grep -rn '\.main_visitor' src/compiler --include='*.iyi' | wc -l` prints 0. The IR validity gate records two files as known failures to verify (STAGE_TWO.md section 4, hole 3). The raise runtime in the port is being retired (STAGE_TWO.md section 4, hole 3).

**Layer 7: artifact format** (`artifact/iyimod.iyi`). Artifact gate pending, mod wiring gate pending. Nothing blocks inspection and dumping, which is wired behind `iyi mod dump --selfhost`.

**Layer 8: command driver, daemon and tools.**
* Driver (`command/driver.iyi`), gate pending. Option parsing and dispatch only. The stage-one gate's comment records that, on 14 September 2026, the driver's build verb "returns without producing a binary". At this commit the entry point that carries the driver does not compile (section 5).
* Daemon (`command/daemon.iyi`), gate pending. The gate covers socket paths, identity and error text, as its own description states.
* Formatter (`tools/formatter.iyi`), gate pending, and the format wiring gate pending. Coverage beyond the gate's own corpus is not measured here.
* Bind (`tools/bind.iyi`), gate pending. The gate's log reports pending.

## 4. The stage-one wiring sequence

Components must be wired in topological dependency order:

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
[Layer 5: Platform Support + LLVM Bindings]
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

Wiring across the Crystal and iyi boundary can only happen where a clean process or file boundary exists. An in-memory boundary, such as passing AST nodes from the iyi parser into Crystal's semantic analyzer, needs full serialization or an FFI bridge between two collectors, which costs more than finishing the port. So the compilation pipeline has to be assembled entirely inside iyi, while standalone tools (`mod`, `format`, `parse`) can be wired now through companion dispatch. The heap boundary is the finding that rules out in-process wiring. `bench/selfhost_stage_one_exercise.sh` names it as the reason stage one is a separate executable.

## 5. The stage-one entry point does not compile

At this commit `bin/iyi` refuses the stage-one entry point. Measured:

```
$ bin/iyi build -o .build/iyi-stage1 src/compiler/stage1.iyi; echo $?
1
```

The refusal is the compiler's own rule for raw memory and C declarations (SPEC.md III.13). `src/compiler/stage1.iyi` line 15 declares `lib LibC` and the module carries no `@[Unsafe]` mark. The first lines of the message say so:

```
In src/compiler/stage1.iyi:15:1
Error: `lib LibC` declares C functions the compiler does not check, and `compiler/stage1` is not marked unsafe (1 more place in this module does the same). If this module handles raw memory, say why above its `module` header: `@[Unsafe("...")]` (SPEC.md III.13)
```

The stage-one gate starts with this same build. Its build step fails and the gate exits without reaching its later checks. Verdict: pending. The gate's summary: pending

The gate's committed floor is `dispatch` (`STAGE1_FLOOR="dispatch"`, `bench/selfhost_stage_one_exercise.sh`, line 84). Its comment, dated 14 September 2026, records that every command the ported driver serves is dispatched, and that the build verb "returns without producing a binary" (lines 80 to 83). That was measured before the refusal above. So the floor is not measured at this commit, and stage one cannot build stage two until its entry point compiles.

## 6. Companion tools wired behind flags

Three companion tools are wired into the shipped CLI through a `--selfhost` flag. They are the only wired components. The routing lives in `src/compiler/iyi/command/*.cr` (`grep -ln run_selfhost src/compiler/iyi/command/*.cr` lists `check.cr`, `format.cr` and `mod.cr`).

* `iyi mod dump --selfhost` runs `.build/iyi-mod`, built from `src/compiler/tools/mod.iyi` (39 lines). Gate pending.
* `iyi tool format --selfhost` runs `.build/iyi-format`, built from `src/compiler/tools/format.iyi` (33 lines). Gate pending.
* `iyi check --parse-only --selfhost` runs `.build/iyi-parse`, built from `src/compiler/tools/parse.iyi` (41 lines). Gate pending.

These are companion processes, so none of them crosses the heap boundary in process (section 4).

## 7. Observable proof of stage one

Stage one is complete when all seven hold. Here is where each stands at 9a2a08173.

1. **The entry point exists.** `src/compiler/stage1.iyi` exists and is 37 lines (`wc -l`). Met as a file.
2. **Crystal builds stage one.** Not met. `bin/iyi build -o .build/iyi-stage1 src/compiler/stage1.iyi` exits 1 (section 5). The gate's verdict: pending.
3. **The executable validates.** Not met, because there is no executable. The gate checks `.build/iyi-stage1 version` against `src/IYI_VERSION` (`0.21.0` at this commit), and it checks help, tool usage and unknown-command refusal.
4. **It compiles a program.** Not met, because there is no stage-one binary to run (section 5).
5. **The output runs and matches.** Not met, because it depends on item 4.
6. **The selfhost gates pass.** There are 23 selfhost gates (`ls bench/selfhost_*_exercise.sh | wc -l`). In the baseline matrix, pending of them exit 0. The gates run against `bin/iyi` and the tools it builds, not against the stage-one binary, so this item measures the port and not stage one.
7. **The dependency floor holds for stage one.** Not measured at this commit. `bench/dependency_floor.sh` was not run against `.build/iyi-stage1`, because that binary is not produced.
