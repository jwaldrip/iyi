# Call lookup parity (slice S1c)

Status of the call lookup port (`method_lookup.iyi`, `match.iyi`, `restrictions.iyi`,
`call.iyi`, `call_error.iyi`) against the hosted call pass. Measured on the pushed
head by `bench/selfhost_semantic_calls_exercise.sh`.

## Fixture parity (measured)

15 fixtures, 146 call sites: every `# call` line (the hosted lookup result) and
every `# error` line (the first line of the hosted error, or `ok`) is byte-identical
to the hosted oracle. 23 guarded mutation proofs, each caught.

## Census over real files (measured)

`bench/selfhost_semantic_calls_census.sh` compares the lookup with the hosted pass on
every call site the hosted pass types in a whole-program entry. Run on the 45 entries
(17 tools under `src/compiler/tools/`, 28 samples), with the floor written from the run:

- **Loaded in the port: 17 files** (all samples the port can load). Sites the hosted
  pass reached: 729. Typed by the hosted pass: 567. Identical: 331, which is 58.4% of
  the typed sites. Per file: `bench/selfhost_semantic_calls.floor`.
- **Did not load in the port: 28 files** (all 17 tools, 11 samples). The census cannot
  measure them until the declarations slice fixes these loader gaps (the port refuses
  or panics on them): `Compiler::Syntax::Lexer is not a class, it's a module`; `can't
  implement Std::Enumerable, it's a module`; `undefined constant ir_quote` and
  `valid_int_bits?` in `compiler/ir/types`; `undefined constant parse_operand` in
  `compiler/native/asm/constraints`.
- **Ranked unresolved shapes:** `type IyiGroup does not resolve` (spawn), `type Channel
  does not resolve` (receive, send, close, new). The port's lookup does not find those
  types in the file's closure (a declarations gap for the samples' concurrency types).
- **Known text differences on identical lookups:** the hosted pass prints a file's
  module as `Name:Module` and the port prints `Name` (a renderer gap in the type
  names, `ModuleType#to_s`, which the types slice owns). A call with a free-variable
  argument (`forall T`) is refused by the port (`free variables are not ported`) where
  the hosted pass gives `undefined constant T`.

The census gate's floor is committed; a count may only rise. It is not in CI's
`*_exercise.sh` glob.

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
