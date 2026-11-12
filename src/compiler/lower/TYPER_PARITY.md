# Typer parity: the lowering against the hosted typer

Measured by `bench/selfhost_lower_types_exercise.sh` on the head of `selfhost/s2b-typer`, for the host target `aarch64-apple-darwin`. A type is identical when the port's block equals the hosted oracle's block byte for byte. A block holds `llvm_type`, `llvm_type(wants_size)`, `llvm_struct_type`, `offsets`, `llvm_embedded_type`, `size`, `align`, `ivars`, `layout` (the pointer map, without the type id), `passed_indirectly`, the proc function types, and the C types.

## Fixtures (bare, gate-compared)

| fixture | types | identical |
|---|---|---|
| `lowty_primitives` | 18 | 18 |
| `lowty_pointers` | 6 | 6 |
| `lowty_enums` | 4 | 4 |
| `lowty_composites` | 6 | 6 |
| `lowty_unions` | 7 | 7 |
| `lowty_procs` | 4 | 4 |
| `lowty_class_explicit` (iyi object layout) | 1 | 1 |
| `lowty_class_layout` (Crystal object layout) | 1 | 1 |
| `lowty_class_pointers` | 2 | 2 |
| `lowty_class_assigned` (ivars typed by assignment) | 1 | 1 |
| **total** | **50** | **50** |

Type ids are gated by shape in `lowtyid_hierarchy` (the port's ids equal the hosted ids shifted by 30). Exact equality waits on NEEDS.md row 16.

## Own source: every type each file declares (the floor)

The whole-program mode (`--own <file> <triple>`) loads the file's import closure with the prelude, as a build does (the hosted oracle prepends the prelude's require; the port loads the prelude file first), declares the instance variables, and prints one block per type the file declares. The gate compares the blocks by type name (`bench/lib/lower_types_compare.py`) and checks each file against `bench/selfhost_lower_types.floor`, which may only rise.

Measured at this head (`LOWER_TYPES_RAISE=1` wrote the floors):

- 125 files under `src/compiler/**/*.iyi`.
- **28 measured** (both sides lower the file). Declared types in them: 963 (the hosted side's count, including nested types). **Identical: 64** of those; 160 differ; the rest are not measured because the port fails the file.
- The hosted oracle fails no file in this run. 97 files fail on the port side, each at its first unported or upstream reason (below).

The per-file counts are the floors in `bench/selfhost_lower_types.floor`. The 28 measured files and their identical counts are in that file.

### Ranked reasons

Differences, by the field that first disagrees (`differs in <field>`): offsets 123 types, `llvm_type` 32, ivars 5.

Port failures (a file the port cannot lower counts zero), by the first line of the port's message: 32 `can't implement Std::Enumerable, it's a module` (trait impl through the closure), 31 `Compiler::Syntax::Lexer is not a class, it's a module`, 19 `can't make class 'Inst' inherit struct 'Value'`, 10 undefined `LibLLVM::...` lib types, 1 `leb.iyi` syntax error, and a few `create_llvm_type ... is not ported` for constants and `AnalysedProgram`.

| reason | types or files | owner |
|---|---|---|
| Instance variables in the wrong order: the port records explicit declarations at `TopLevelVisitor#finish`, after the guessed ones and the constructor arguments; the hosted pass keeps declaration order. Every offset after the first mis-ordered field differs. | most of the 123 offset differences | declarations trunk: `agent://S1b5Declarations` (`semantic/top_level.iyi` pending ivars, `instance_vars.iyi`) |
| Generic instance ivar types lose their arguments (`@pool : Hash(String, String)` prints `Hash`). | 5 ivars | declarations trunk (NEEDS.md row 3) |
| A module with implementors lowers as the mixed union of its implementors in the hosted typer. The port answers `i32` (the namespace answer) for it. | part of the 32 `llvm_type` | lowered types (`agent://S2b2Typer`, NEEDS.md row 5): open |
| Constants and `AnalysedProgram` are not typed: `create_llvm_type` raises. | 4 files | lowered types (`agent://S2b2Typer`, new NEEDS row) |
| `Std::Enumerable` trait impl and `Lexer` module-vs-class fail in the closure. | 63 files | declarations trunk and bodies (`agent://S1b5Declarations`, `agent://S1d2Bodies`) |
| `Inst` inherits the struct `Value`. | 19 files | declarations trunk |
| `LibLLVM` lib types are not declared in the closure. | 10 files | declarations trunk |

Settled in this increment, not in the ranking:

- A namespace module (`module Compiler::Foundation`) answers `i32`, the hosted answer for every namespace measured with the prelude loaded.
- A struct's by-value answer and a module's by-value answer follow the hosted `passed_by_value?` (codegen/types.cr). The port's `including_types` also holds nested namespaces, so a module's answer is not yet split on implementors.
- The prelude is loaded in both sides. The oracle was not loading it before; its `iyi_object_layout?` was therefore false and the port's true.

## Hello and the prelude

`samples/iyi/hello.iyi` with the prelude: not yet measured. The own-source mode covers the prelude's own declared types only when the prelude file itself is the entry. It is the next increment after the declarations fixes above.

## Gate figures

- Fixtures: 10 identical (50 types), 0 diverged.
- Own source: 28 measured, 64 identical of 963 declared, floors in `bench/selfhost_lower_types.floor`.
- Mutations: 28 caught, including the own-source probes (a namespace module as `if false`, and a struct's by-value answer removed), which fail when a probe file's identical count drops below its floor.
