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

## Measured

Gate: `bench/selfhost_pipeline_exercise.sh` (floor `bench/selfhost_pipeline.floor`).

| rung | program | phase reached | first refusal |
|---|---|---|---|
| 1 | the 60 fixtures of the four lowering gates (`lower_*`, `lowcall_*`, `lowprim_*`, `lowglob_*`), no prelude | `run-equal` for 48, a refusal for 12 | see below |
| 2 | `samples/iyi/hello.iyi`, `--prelude` | declarations pass, refuses in bodies | `bodies: BUG: node has no type: @[Primitive(:class)]` |
| 3 | `src/compiler/tools/parse.iyi`, `--prelude` | parse passes, refuses in declarations | `undefined constant StringPool` (lexer.iyi import) |
| 4 | `src/compiler/tools/compile_native.iyi`, `--prelude` | parse passes, refuses in declarations | `can't make class 'Inst' inherit struct 'Value'` |

Rung 1: each of the 48 fixtures that reach link is built to an executable, run, and its stdout and
exit status equal the hosted executable for the same fixture (built with `--prelude empty`). The 12
refused fixtures exit 1 and write no output:

- `bodies`: `lower_sizeof`, `lower_typeof`, `lower_pointer_of`, `lower_instance_sizeof`, `lower_tuple`,
  `lower_named_tuple` (`BUG: node has no type`); `lower_multi_assign`, `lower_out`, `lower_underscore`
  (`undefined local variable or method`); `lowcall_types` (argument restriction); `lowprim_ptr`
  (`undefined method 'malloc' for Pointer(Int32).class`).
- `lower`: `lowprim_checked` (`visit(FunDef)` is not ported in `lower/lower.iyi`).

The gate also proves: the tool links no LLVM (`otool -L`); mutations of the refusal path
(a refusal exits 0), of the program assembly (top-level code dropped), and of the tool's refusal
exit (fallback to the codegen pipeline) are each caught.

## Refusals ranked, with owners

Ranked by the number of fixtures or roots they stop, from the measurements above.

1. `BUG: node has no type` for sizeof, typeof, pointerof, instance_sizeof, tuple and named tuple literals
   (6 fixtures; plus the `@[Primitive(:class)]` node in hello). Owner: bodies, S1d2Bodies. Tuple literals
   are reported implemented on that slice pending a merge.
2. `undefined local variable or method` for multi-assignment, `out` and `_` (3 fixtures). Owner: bodies, S1d2Bodies.
3. `undefined constant StringPool` in `parse.iyi` (lexer.iyi import of `compiler/foundation/string_pool`),
   and `can't make class 'Inst' inherit struct 'Value'` in `compile_native.iyi` (superclass check). Owner:
   declarations and module rules, S1b6Declarations. A head that fixes the import order is 613623afc
   on `origin/selfhost/s1b-declarations`; not yet merged here.
4. `lower: visit(FunDef)` (1 fixture). Owner: core, S2a3Core (the dispatch in `lower/lower.iyi`).
5. Argument restriction in `lowcall_types` and `undefined method 'malloc'` in `lowprim_ptr` (1 fixture each).
   Owner: calls, S1c3Calls.

## Not yet measured

- Per-def counts (how many defs were typed, how many lowered) and a ranked refusal table across defs for the
  prelude roots. The bodies table is S1d2Bodies'; it is not yet published (today `typed_dump` prints one
  `untyped:` line per node). The lowering refuses at its first refusal per program, so the lowered count
  is not available without lowering each def on its own.
- The source location of a lowering refusal. `refuse_port` in the lowering carries no node location.
- Whole program from source through the loader's module rules (step 5): the import closure resolves for
  the roots above, but the declarations pass refuses on the first import rule it does not yet match.

## Next step

Merge `origin/selfhost/s1b-declarations` once its successor to 613623afc is pushed, re-run
`bench/selfhost_pipeline_exercise.sh`, and raise the floor for `src/compiler/tools/parse.iyi` and
`src/compiler/tools/compile_native.iyi` if they move. Then report the ranked table from S1d2Bodies in
place of the list above.
