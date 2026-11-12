# Typer parity: the lowering against the hosted typer

Measured by `bench/selfhost_lower_types_exercise.sh` on the head of `selfhost/s2b-typer`, for the host target `aarch64-apple-darwin`. A type is identical when the port's block equals the hosted oracle's block byte for byte. A block holds `llvm_type`, `llvm_type(wants_size)`, `llvm_struct_type`, `offsets`, `llvm_embedded_type`, `size`, `align`, `ivars`, `layout` (the pointer map, without the type id), `passed_indirectly`, the proc function types, and the C types (`c_type`, `c_return_type`, `embedded_c_type`, `intrinsic_return_type`).

## Fixtures, gate-compared

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
| **total** | **49** | **49** |

Type ids are gated by shape in `lowtyid_hierarchy`: the port's ids equal the hosted ids shifted by 30 across every value. Exact equality waits on NEEDS.md row 16.

Types in `lowtywait_*` fixtures are not counted. They are the property declarations, the assignment-typed instance variables, the generic class instance, and the builtins' ids. Each waits on its row in NEEDS.md.

## Own source and hello.iyi: not measured

Measured quantities, both counted from the tree and not from the lowering:

- `src/compiler/**/*.iyi`: 538 declared type lines (class, struct, enum, module, lib, union, alias, trait) in 123 files.
- `samples/iyi/hello.iyi` with the prelude: the set of types the hosted typer is asked for. Not enumerated.

Identical of total: **0 of 538** for the own source and **0 of N** for hello.iyi. Both are zero for the same reason: the lowering driver loads one file bare, with no prelude and no import closure. Every own-source type either refers to a type declared in another file (unresolved) or has an instance variable the port records no type for (NEEDS.md rows 14 and 15). Measuring the whole tree needs the import closure that the declarations gate already loads (`bench/selfhost_semantic_declarations_oracle.cr`), and the hosted prelude. Those are the next steps.

## Reasons for a difference, ranked

Ranked by what they block in the own source, from the declarations and not from a count: a type with a blocked reason cannot be measured at all, so the reasons are listed by how many types each would block once the lowering reaches them.

1. Instance variables assigned in `initialize` have no recorded type (NEEDS.md row 15). Most classes in the compiler assign their fields that way, so this blocks the most types.
2. `property` and `getter` declarations are not expanded in a bare program (NEEDS.md row 14). Both sides fail on them.
3. Instance variables of a generic class instance have no `all_instance_vars` (NEEDS.md row 3). Every generic class in the source is blocked by this.
4. The builtins are struct classes in the port, not primitives (NEEDS.md row 1). The name adapter in `typer.iyi` covers the lowering, and it does not cover the ids (row 16).
5. Type ids differ by the builtins' numbering (NEEDS.md row 16). Ids are not in the block gate; they are gated by shape only.
6. Metaclasses of generic instances have no answer (NEEDS.md row 2).
7. A module member of a union is not expanded (NEEDS.md rows 5 and 7).
8. The struct store size omits tail padding in `ir/layout.iyi` (NEEDS.md row 9). The typer pads the struct itself, so the blocks agree, but the layout module is wrong for other callers.

Found during the work and fixed, so they are not in the ranking: the builtins' by-value rule, the mixed union's by-value rule (`MixedUnionType`), the uninitialised-ivar hosted error (the fixtures initialise every declared variable), and the alias node that the main visitor cannot type (the driver visits class definitions only).
