# Typer parity: the lowering against the hosted typer

Measured by `bench/selfhost_lower_types_exercise.sh` on the head of `selfhost/s2b-typer`, for the host target `aarch64-apple-darwin`. Each row is one type, and it is identical when the port's block (`llvm_type`, `llvm_type(wants_size)`, `llvm_struct_type`, offsets, `llvm_embedded_type`, size, alignment, `passed_by_value`) equals the hosted oracle's block byte for byte.

## Fixtures (live, gate-compared)

| fixture | types | identical |
|---|---|---|
| `lowty_primitives` | 18 | 18 |
| `lowty_pointers` | 6 | 6 |
| `lowty_enums` | 4 | 4 |
| `lowty_composites` | 6 | 6 |
| `lowty_unions` | 7 | 7 |
| **total** | **41** | **41** |

Types listed as `# waiting` in the fixtures are not counted. They wait on the rows of `NEEDS.md`: generic instance metaclasses, `StaticArray` and `NamedTuple`/`Proc` resolution, and class instance variables.

## Own source and the hello sample: not measured

The acceptance asks for the same comparison on every type the hosted typer is asked for when it compiles `samples/iyi/hello.iyi`, and on every type declared in `src/compiler/**/*.iyi`. That measurement is not built. Both sides need the same analysed program: the hosted compile's front end, with the prelude and the import closure, on the oracle side, and the port's declarations and semantic pass on the port side. The port's declarations do not yet type instance variables (NEEDS.md row 12), and the hosted front end is not called from the lowering driver. Without those two, every class or struct in the port's own source fails the lowering with a BUG error, so a count would measure the declarations slice, not the typer. The next increment (below) builds the measurement once row 12 is closed.

## Reasons for a difference, in the order they came up

These are the differences the gate found while the fixtures were being brought to parity. Each is recorded so the same class does not reappear unnoticed.

1. Builtins are plain structs in the port (`NonGenericClassType`, NEEDS.md row 1), not primitive classes. The hosted typer sees `Int32` as `i32` by its `bytes`; the port sees a struct. The typer recognises builtins by name. This accounted for every primitive mismatch before the adapter.
2. A generic instance's metaclass is nil in the port's unification (NEEDS.md row 2). The fixture line is waiting.
3. Struct store size: LLVM pads a struct to its alignment, the port's `store_size` (`ir/layout.iyi`) does not (NEEDS.md row 9). The typer pads the struct itself; `lowty_composites` and `lowty_unions` show the padded value.
4. The oracle's and the driver's type resolvers took only plain names; unions, nilable types, and numeric or named arguments needed a resolver each (NEEDS.md rows 11 and 13). The union and nilable forms are now resolved on both sides.
5. A mixed union is a `MixedUnionType` in the port, not a plain `UnionType`, so the by-value rule must name it. Found by a mutation that the first gate run did not catch.
