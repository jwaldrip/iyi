# The typed pipeline: status

The typed pipeline takes one program from source to a native executable through the typed analysis
and the typed lowering, with no LLVM and no host tool. It is `compile_typed` in `compiler/compiler.iyi`
and the program assembly in `compiler/lower/program.iyi`, reached from `iyi-compile-native <program.iyi>
-o <exe> --pipeline typed [--prelude] [--probe-phase] [--emit ir]`. The default pipeline is still the
codegen path; the integrator flips it.

Phases, in order: `parse`, `declarations`, `bodies`, `lower`, `verify`, `native`, `link`. With
`--probe-phase` each phase prints `[phase] X: start`, then `[phase] X: pass` when it passes. A refusal
prints `X: fail: <message>` and `reached: <last pass>` and writes no output. A refusal that exits the
process (`refuse_port`, which the semantic passes call) prints no `reached:` line: the last `[phase] X:
start` without a pass names the refusing phase, and the last pass is what it reached.

The declarations phase reads the program the way the declarations gate does (`declare_unit` in
`lower/program.iyi`): one visitor per unit in initialiser order, the prelude first, with the loader's
search path and the entry's project root. Each unit is keyed by the import resolver's normal path. Every
top-level def is kept (overloads included), since `extract_declarations` keeps one def per name.

## Measured

Gate: `bench/selfhost_pipeline_exercise.sh` (floor `bench/selfhost_pipeline.floor`).

| program | phase reached | refusal |
|---|---|---|
| the 60 fixtures of the four lowering gates (`lower_*`, `lowcall_*`, `lowprim_*`, `lowglob_*`), no prelude | `link` with run-equal for 49, a refusal for 11 | see below |
| `samples/iyi/hello.iyi`, `--prelude` | declarations | bodies: `BUG: node has no type: @[Primitive(:class)]` |
| `src/compiler/tools/parse.iyi`, `--prelude` | declarations | the same bodies refusal |
| `src/compiler/tools/compile_native.iyi`, `--prelude` | declarations | the same bodies refusal |

Run-equal: each fixture that reaches link is built to an executable, run, and its stdout and exit status
equal the hosted executable for the same fixture (built with `--prelude empty`). The 11 refused fixtures
exit 1 and write no output:

- `bodies`: `lower_sizeof`, `lower_typeof`, `lower_pointer_of`, `lower_instance_sizeof`, `lower_tuple`,
  `lower_named_tuple` (`BUG: node has no type`); `lower_multi_assign`, `lower_out`, `lower_underscore`
  (`undefined local variable or method`); `lowprim_ptr` (`undefined method 'malloc' for Pointer(Int32).class`).
- `lower`: `lowprim_checked` (`visit(FunDef)` is not ported in `lower/lower.iyi`).

The gate also proves: the tool links no LLVM (`otool -L`); mutations of the refusal path (a refusal
exits 0), of the program assembly (top-level code dropped), and of the tool's refusal exit (fallback to
the codegen pipeline) are each caught.

## Refusals ranked, with owners

1. `BUG: node has no type: @[Primitive(:class)]` in the body of `class Object` (src/iyi/primitives.iyi:36),
   which stops every prelude root. The iyi parser keeps the annotation as a body expression; the hosted
   parser attaches it to the following def (parser.cr:5738). Owner: bodies, S1d2Bodies, which is making
   `visit(Expressions)` skip annotation members.
2. `BUG: node has no type` for sizeof, typeof, pointerof, instance_sizeof, and tuple and named tuple literals
   (6 fixtures). Owner: bodies, S1d2Bodies (tuple literals are implemented there pending a merge).
3. `undefined local variable or method` for multi-assignment, `out` and `_` (3 fixtures). Owner: bodies, S1d2Bodies.
4. `visit(FunDef)` (1 fixture). Owner: core, S2a3Core (the dispatch in `lower/lower.iyi`).
5. `undefined method 'malloc' for Pointer(Int32).class` (1 fixture): a class method on the metaclass of a
   generic instance has no lookup path. Owner: calls, S1c3Calls (diagnosed, not yet fixed).

Resolved on this head: `undefined constant StringPool` (parse.iyi) and `can't make class 'Inst' inherit
struct 'Value'` (compile_native.iyi), which the declarations path no longer raises; `lowcall_types` now runs
equal (its two overloads are in the root).

## Not yet measured

- Per-def counts and a ranked refusal table across defs for the prelude roots. Continuing past the first
  refusal needs total mode in the bodies pass (`MainVisitor#total`, `SemanticProgram#total_mode`) and the
  table S1d2Bodies is building. The lowering stops at its first refusal per program, so the lowered count
  is not available without lowering each def on its own.
- The source location of a lowering refusal (`refuse_port` in the lowering carries no node location).
- The hosted pass's own whole-program declarations gate (bench/selfhost_semantic_declarations_exercise.iyi
  `--total`) is the reference for the declarations path; the pipeline's declarations now follow it.

## Next step

Re-run `bench/selfhost_pipeline_exercise.sh` once S1d2Bodies pushes the annotation skip, then raise the
floor for the three prelude roots from declarations to whichever phase they reach. Then add total mode
for the prelude roots and report the ranked table in place of item list above.
