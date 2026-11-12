# Members the lowering needs from the analysed program

Each row is a member, or a model fact, that the typer in `src/compiler/lower/typer.iyi` needs and the port's analysed program does not provide as the hosted typer expects. Nothing here is edited in another slice's file. The typer works around a row where it can, names the workaround, and raises a BUG error where it cannot. A fixture that waits on a row is written as a `# waiting` line, not a `# type` line, so the gate does not compare it.

| # | Member or fact | Hosted source | Port today | Read by (typer function) | Waiting fixture |
|---|---|---|---|---|---|
| 1 | Builtins are primitive classes (`IntegerType`, `FloatType`, `CharType`, `BoolType`, `SymbolType`, each with `bytes`) | `src/compiler/iyi/types.cr` (`PrimitiveType`), the hosted program's builtins | Every builtin is a `NonGenericClassType` with `struct = true` (`src/compiler/semantic/top_level.iyi` 1019-1051) | `primitive_kind`, `primitive_bytes`, `create_llvm_type`, `passed_by_value?` | `lowty_primitives` is live, through the name adapter in `typer.iyi`. Remove the adapter when S1a/S1b build the primitive classes. |
| 2 | A generic instance's metaclass | `Type#metaclass` on `GenericClassInstanceType` (`GenericClassInstanceMetaclassType`) | `TypeUnification.metaclass_of` returns nil for `Pointer(Int32)` (`src/compiler/types/unification.iyi`) | the driver's `resolve` for `T.class` | `lowty_enums`: `# waiting: Pointer(Int32).class` |
| 3 | `all_instance_vars` on a generic class instance (the instance variables of `Box(Int32)`, with their types substituted) | `ClassType#all_instance_vars` with generic instances as `GenericClassInstanceType < ClassType` | `GenericClassInstanceType < GenericInstanceType < Type` has no `all_instance_vars` (`src/compiler/types/types.iyi` 144) | `instance_var_struct` (raises BUG for generic instances) | not yet written: a `lowty_generic_class` fixture |
| 4 | `extern?`, `extern_union?`, `packed?` on a class | `NonGenericClassType#extern?` etc. (`src/compiler/iyi/types.cr`, `lib.cr`) | Absent from the port's `ClassType` | `llvm_name` of `lib` structs, `create_llvm_c_union_struct_type`, `packed` struct fields (increment 5) | a `lowty_lib_structs` fixture, after the declarations slice builds lib structs |
| 5 | `including_types` as one type (the union of the including types, or nil) | `ModuleType#including_types` returns `Type?` (`src/compiler/iyi/types.cr`) | `ModuleType#including_types : Array(Type)` (`src/compiler/semantic/top_level.iyi` 225) | `passed_by_value?` for a module (raises BUG if one has including types), a module member of a union (raises BUG) | a `lowty_modules` fixture |
| 6 | `ReferenceStorageType` (a `reference_storage` wrapper with `reference_type`) | `ReferenceStorageType` in `src/compiler/iyi/codegen/llvm_typer.cr` 269 | Absent | `create_llvm_type` (not yet ported; falls to the BUG raise) | none |
| 7 | Module members of a union are not expanded (the mixed union itself is `MixedUnionType`, as hosted) | `MixedUnionType` in `src/compiler/iyi/types.cr`, and `expand_union_types` (`src/compiler/iyi/codegen/types.cr` 111-179) | A mixed union is a `MixedUnionType` (`src/compiler/types/types.iyi`); a module member is not expanded | `create_llvm_type` (`mixed_union_struct`) and `passed_by_value?` (the `MixedUnionType` clause). Module members raise BUG. | `lowty_unions` is live; the module-member case waits on row 5. |
| 8 | `llvm_name` as the hosted codegen spelling (`to_s_with_options codegen: true`) | `Type#llvm_name` (`src/compiler/iyi/codegen/types.cr` 101-109) | The typer uses `full_name` for struct names (`llvm_name` in `typer.iyi`) | struct names of tuples and classes | `lowty_composites` agrees for tuples; a class struct fixture would show any other difference |
| 9 | Store size of a struct with tail padding | `LLVMStoreSizeOfType` | `compiler/ir/layout.iyi` `store_size` sums to the end of the last field without the tail padding LLVM adds. The typer's `size_of` pads the struct itself. | `size_of` in `typer.iyi` | `lowty_composites` (`Tuple(Int32, Bool)`, size 8) and `lowty_unions` agree only because the typer pads. The owner of `ir/layout.iyi` should make `store_size` of a struct round up to the struct's ABI alignment, as LLVM's `StructLayout` does. |
| 10 | `Program#size_bit_width` | `program.cr` | `Target#size_bit_width` exists (`src/compiler/platform/target.iyi`) | `size_t` | none |
| 11 | The oracle's and the driver's type resolvers take a number argument (`StaticArray(Int32, 4)`) | the hosted type of a static array is built from a `NumberLiteral` size | The resolvers in `bench/selfhost_lower_types_oracle.cr` and `bench/selfhost_lower_types_exercise.iyi` take types only | `StaticArrayInstanceType` lowering, which is ported and unmeasured | `lowty_composites`: `# waiting: StaticArray(Int32, 4)` |
| 12 | Instance variables are typed only after the declarations pass | the hosted `TypeDeclarationVisitor` and instance variable initialisers, run by the compile's front end (`bench/selfhost_semantic_declarations_oracle.cr` uses it) | The lowering driver runs `TopLevelVisitor` alone, so `var_type` is nil and `instance_var_struct` raises BUG | `instance_var_struct` (classes and structs, increment 2) | a `lowty_classes` fixture, once both drivers run the declarations pass |
| 13 | `Proc(A, B)` and `NamedTuple(x: A)` in the resolvers | `Proc` is `program.proc_of`; `NamedTuple` takes named arguments | The resolvers do not parse either | `proc_struct` (increment 2, the `->` pair), `closure_type` and `function_type` (increment 5) | `lowty_composites`: `# waiting: NamedTuple(...)` and `Proc(Int32, Int32)` |

## Notes for the owners

- Row 1 is the one the typer depends on today. Until it is fixed, `Bool`, `Char`, `Symbol` and the integers reach the typer by name. Any builtin added to the prelude under another name needs a branch in `primitive_kind`.
- Row 9 is in `src/compiler/ir/layout.iyi`, which this slice does not own.
- Row 12 is the gate for every class-shaped increment: until the declarations pass runs in the drivers, no class fixture can be measured.

## Lowering core (S2a): what the core reads and the port does not yet give

The gate (bench/selfhost_lower_core_exercise.sh) compares the core's module with the hosted module of each fixture. These rows are what the core needs and where it stands.

| Member or fact | Hosted line | Port today | Who fixes it |
|---|---|---|---|
| `visit(FunDef)` and `codegen_fun` | codegen.cr:842, fun.cr | refused by name in `pending.iyi` (`pending_visit_fun_def`) | S2c |
| `visit(Call)` and `codegen_call` | codegen.cr, call.cr | refused by name in `pending.iyi` (`pending_visit_call`) | S2c |
| IR block removal for an empty alloca block | codegen.cr:741 (`alloca_block.delete`) | removes the block from `Function#blocks`; its name stays in the symbol table | the IR owner (`ir/function.iyi`) |
| Store alignment from the stored type | codegen.cr:612 (`set_align`) | `Inst#alignment=` set from `LowerTyper#align_of` | the typer owner for the table; the IR owner for `alignment=` |
| Call function type in the printed text | LLVM 22 prints `call T @f(A)` | the gate writes `call T (types) @f(A)` into the oracle before the port reads it | the IR text parser owner (`ir/parser.iyi`), if LLVM text is to be read unrewritten |
| Call-site attribute groups `#N` after a call | LLVM prints them | the gate drops them, as it drops the attribute groups | the IR text parser owner |
| The `%Nil` named type | the hosted normaliser also drops `%Nil` | `LowerTyper#nil_type` declares it when `const_undef` of `Nil` is built | the typer owner (no change needed for the gate) |
| Calling convention of `__crystal_main` and `main` | codegen.cr:2456 (`define_main_function`, C calling convention) | `CallConv::C` set explicitly | the core (done) |
| `printf` declaration from constant printing | codegen.cr printf helper | dropped by the gate on both sides | the constants slice (S2e) |
| `Crystal::BUILD_*` globals and stores | `codegen.cr` constant initialisation | not emitted; dropped by the gate on both sides | the entry owner when the build identity is ported (S2g) |
| Phi incoming pairs without the `label` keyword | LLVM 22 prints `[ 1, %then ]` | the gate writes `label` into the oracle's phi pairs before the port reads it (same as the call type) | the IR text parser owner, if LLVM text is to be read unrewritten |
| The `if` with a literal condition | codegen.cr:1330 (`node.truthy?` folds it, no blocks) | not ported: a literal condition is refused by name by the lowering reaching it (`pending_visit_node`) | the core owner, with the typed truthiness (S2c or a later increment) |
| The `if` with a non-Bool condition | cond.cr (`codegen_cond` of a union or nilable type) | refused by name in `cond.iyi` | S2c |
