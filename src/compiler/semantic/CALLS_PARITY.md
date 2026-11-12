# Call lookup parity (slice S1c)

Status of the call lookup port (`method_lookup.iyi`, `match.iyi`, `restrictions.iyi`,
`call.iyi`, `call_error.iyi`) against the hosted call pass. Measured on the pushed
head by `bench/selfhost_semantic_calls_exercise.sh`.

## Fixture parity (measured)

15 fixtures, 146 call sites: every `# call` line (the hosted lookup result) and
every `# error` line (the first line of the hosted error, or `ok`) is byte-identical
to the hosted oracle. 23 guarded mutation proofs, each caught.

## Census over real files (not yet a figure)

`bench/selfhost_semantic_calls_census.sh` (with `selfhost_semantic_calls_census_oracle.cr`
and `selfhost_semantic_calls_census_exercise.iyi`) compares the lookup on every call
site the hosted pass types in a file. Its first figure is not yet produced, for two
reasons, both outside this slice:

1. **The hosted pass types a call only when its def is reached.** A library file
   compiled as an entry has almost no typed call sites: `match.iyi` has none, and
   `src/iyi/array.iyi` has none under `--prelude-only`. A per-file census of library
   code therefore measures almost nothing. A meaningful census needs the call sites
   of whole programs (the tool entries, the samples), counted per file across every
   program that reaches them.
2. **The declarations loader refuses a def import.** `import compiler/foundation/errors::{refuse_port}`
   is refused because `refuse_port` is a module-level `def`, not a type or constant.
   Every real file that reaches `top_level.iyi` therefore fails to load in the port,
   which blocks the census of the compiler's own source.

## Ranked gaps the fixtures show

Each is a divergence the hosted pass resolves and the port does not. They are the
next slices of work, in the order the fixtures found them:

1. **A restricted splat parameter** (`Array#push(*values : T)` on `Array(Greet)` with an
   `Int32` argument). The port refuses it (`a restricted splat parameter is not ported`);
   the hosted pass answers `none` for `# call` and the restriction message for `# error`.
   See `bench/fixtures/semcall_trait_impl.iyi`.
2. **A call on a trait-typed receiver dispatches to the implementers.** `Holder.one().greet()`
   with `one : Greet` resolves in the hosted pass (`ok`) through the trait's implementers;
   the port finds only the abstract declaration and reports `no overload matches`.
   See `bench/fixtures/semcall_trait_impl.iyi`.
3. **Overloads by restriction specificity.** Fixed in this slice: the most specific of
   the accepting defs is chosen (declared restrictions compared by subtype), and the
   cover flag is the chosen def's exactness. See `bench/fixtures/semcall_overloads.iyi`.
4. **The reported stack overflow in the lookup on a class implementing a trait** was not
   reproduced by any fixture here (the trait fixtures, the `new`-with-initialize
   fixture, and a trait restriction on an `Int32` literal all terminate). The repro
   belongs to the bodies slice; it needs the exact call before it can be pinned.
5. Not yet ported: `super` and `previous_def` (the hosted pass answers them outside lookup),
   default arguments, `[]` and `[]?`, `==` falling back to `Object#==`, class methods on
   generic types beyond `new`, named-argument error messages, `call_error.cr`'s
   protected calls, `restrictions_augmenter.cr`.

## Entry points

- `CallRecalculation.recalculate` takes argument nodes and types literal arguments
  (the fixture seed).
- `CallRecalculation.recalculate_signature(rec_type, ts, signature, explicit)` takes a
  `CallSignature` of already-typed arguments and returns the same `CallTarget`. The
  bodies slice calls this one.
