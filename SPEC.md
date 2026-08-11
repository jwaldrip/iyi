# iyi Language Specification — Draft 0

**Status: draft for discussion. Nothing here is implemented.**

This draft deliberately does *not* re-describe the six rules. Each has been
validated on its own — by the Kemal port, by the instantiation census, by the
runtime benchmark. What has never been checked is how they behave **against each
other**, and that is where language projects fail. So Part II, the interaction
matrix, is the substance of this document.

Decisions are marked:

- **SETTLED** — follows from measurement or from a rule already accepted.
- **PROPOSED** — my recommendation, with reasoning; yours to accept or reject.
- **OPEN** — genuinely undecided, needs a call.

---

## Part I — Premises

The compilation model, stated only as far as Part II needs it.

| Rule | Premise |
|---|---|
| R-1 | A module is the unit of compilation. `import` forms a DAG. Compiling a module reads only its dependencies' **export metadata**, never their bodies. |
| R-2 | Everything a module exports (`pub`) carries full parameter and return types. Non-exported code infers. |
| R-2b | `using` brings a module's exported names into unqualified scope, written by the consumer. |
| R-3 | Open classes are gone. `impl Trait for Type` must live in the module defining the trait or the type. |
| R-4 | Generic calls crossing a module boundary pass a dictionary keyed on GC shape. Within a module, monomorphisation. `@[Monomorphize]` forces specialisation across a boundary. |
| R-5 | Macros are derive-scoped: they see the declaration they are attached to, and nothing global. |

Union types, nil-safety flow typing, blocks, local inference and Ruby syntax are
kept unchanged from Crystal. They cost the compiler nothing.

---

## Part II — Interactions

### II.1 Union types × traits — **SETTLED**

The question: can you write `impl Greet for String | Int32`?

**No. Union impls are not writable. A union implements a trait if and only if
every member implements it.**

```
impl Greet for String    # ok
impl Greet for Int32     # ok
# String | Int32 now implements Greet, automatically.

impl Greet for String | Int32   # ERROR: cannot impl a trait for a union
```

Why this and not explicit union impls:

- **No new coherence rule is needed.** If unions were implementable, you would
  have to decide what happens when both `String` and `String | Int32` have an
  impl, and every answer is a footgun.
- **Dispatch already exists.** A union value carries a type id; calling a trait
  method on it compiles to the switch Crystal already generates. No new
  machinery.
- **It composes.** `Array(String | Int32)` works with any trait both members
  implement, without anyone writing anything.

A consequence worth noticing, because it is a feature rather than an accident:
`T?` is `T | Nil`, so **`T?` implements a trait only if `Nil` does too.** In the
Kemal port `Nil` implements `IntoBody` (returning `""`), so `String?` is
returnable from a route. Where `Nil` does not implement a trait, the nilable
type is rejected at compile time — nil-handling is forced at exactly the point
it matters.

### II.2 Union types × dictionaries — **SETTLED**

The question: a union is already a boxed (type id, payload). Is that a
dictionary? Do the two dispatch mechanisms collide?

**They are orthogonal, and the rule is: a union is one type with one shape.**

|  | Union | Dictionary |
|---|---|---|
| What varies | the **value**'s runtime type | the **type parameter**, erased to a shape |
| What is fixed | the code | the value's layout |
| Dispatch | switch on type id carried by the value | indirect call through ops passed alongside |

So `T = String | Int32` receives **one** dictionary, not two — the union is a
single type whose shape is `UNION(PTR|SCALAR4)`. Inside the shared body, a trait
call on a `T` value still switches on the union's type id exactly as it would in
monomorphic code.

This is worth stating explicitly because the intuition "unions are already
dynamic, so they must be dictionaries" is wrong and would lead someone to build
two parallel dispatch systems.

### II.3 `using` × everything — **PROPOSED**

The Kemal port proved `using` is required: without it, Kemal's DSL is
unwritable, because Crystal achieves it by injecting top-level methods into the
importing program's global namespace. But the port did not say what `using`
*is*. Proposed rules:

**1. `using` affects unqualified calls only. It never affects method resolution
on a receiver.**

```
using kemal::dsl

get "/" do |env| ... end     # unqualified -> resolved via `using`
user.greet                   # receiver call -> resolved via User's traits only
```

This single rule dissolves the `using` × traits question entirely: they operate
in disjoint namespaces and cannot interact. Trait method resolution is always
and only a function of the receiver's type and its impls.

**2. Local definitions beat imported ones. Always.**

Defining your own `get` shadows an imported `get`, with no ambiguity error. A
library can never break your code by adding an export that collides with
something you already had.

**3. Ambiguity is an error at the point of *use*, not the point of import.**

```
using a          # exports get, post
using b          # exports get, delete

post "/x" do ... end     # fine
get  "/x" do ... end     # ERROR: `get` is ambiguous (a::get, b::get) — qualify it
```

Resolvable from export metadata alone, so it costs nothing. And it means adding
an export to a library only breaks consumers that actually call the colliding
name.

**4. File-scoped, declared at the top. No block-scoped `using`.**

Block-scoped imports are Ruby's `instance_eval` in a new hat: they make the
meaning of a bare name depend on where you are in a file. Not worth it.

**5. Selective form available and encouraged:**

```
using kemal::dsl                    # everything exported
using kemal::dsl::{get, post}       # just these
```

**OPEN:** whether `using` may be re-exported (`pub using`), so a facade module
can pass a DSL through. Convenient for `import kemal` giving you the DSL without
a second line — and a way to reintroduce exactly the implicitness R-3 removed.
Recommend **no** for Draft 0.

### II.4 Derive macros × separate compilation — **SETTLED**

This is the interaction that decides whether R-5 delivers the caching it
promises.

**A derive runs once, in the module that declares the type. Its output is part
of that module's export metadata. Consumers never re-run it.**

```
# module app/user  — the derive expands HERE, once
pub struct User
  derive JSON
  getter name : String
end

# module app/api
import app/user
user.to_json      # reads export metadata; no macro expansion happens here
```

Coherence holds automatically: `derive JSON` generates `impl ToJSON for User`,
which lives in `User`'s own module — legal under R-3. And you cannot derive a
trait for a type you do not own, which is the orphan rule again, consistently.

**What a macro may read — the precise version of R-5:**

> A macro may read the declaration it is attached to, and the **export metadata**
> — never the bodies — of imported modules. It may not enumerate types it was
> not given.

This is more permissive than "module-local" and still separately compilable.
It matters for the realistic case:

```
pub struct Order
  derive JSON
  getter customer : Customer     # imported from another module
end
```

Expanding `derive JSON` here needs to know only whether `Customer` implements
`ToJSON` — a fact in `Customer`'s export metadata. It never needs
`Customer`'s method bodies. Bounded, cacheable, correct.

What this forbids, and should: `all_subclasses`, program-wide `macro finished`,
and `macro_run` — the last of which was measured at **21% of a cold Crystal
build** from a single call site.

### II.5 Dictionaries × the garbage collector — **SETTLED, and a dependency**

This one only became visible while writing the spec, and it removes a choice I
had previously presented as free.

Shape-based stenciling means one compiled body serves many types. That body must
still tell the collector which words in a value are pointers. **The pointer map
therefore has to travel with the shape** — which is exactly why Go calls it a
*GC shape* rather than a memory layout.

Consequences:

- **R-4 requires a precise collector.** Crystal's Boehm GC is conservative: it
  guesses at pointers by scanning. That works without shape information, but it
  cannot supply the per-shape pointer maps stenciling needs.
- So "replace Boehm with a precise GC" is **not** an independent runtime
  decision to be taken later. It is a prerequisite of R-4, and it constrains
  object layout from day one.
- Recommended: precise, generational, **non-moving** for Draft 0. Moving
  collection requires interior-pointer discipline throughout, and Crystal's
  `to_unsafe`/`Pointer` idioms are pervasive. Defer.

---

## Part III — Open questions, with recommendations

### III.1 Errors — **PROPOSED, developed**

Errors are ordinary union members. No `Result` wrapper, no exception hierarchy,
no new type machinery — unions already exist and already carry a type id.

```
pub def read(path : String) : String | IOError
```

#### III.1.1 What makes a member an error — **PROPOSED**

A prelude marker trait:

```
pub trait Error
  def message : String
end
```

A union member is an *error member* if its type implements `Error`. This needs
no new syntax and composes with II.1: `IOError` is a normal type that happens to
implement a normal trait.

Two degenerate cases are rejected at compile time rather than given surprising
meanings:

- `def f : IOError` — not a union, nothing to propagate. `f()!` is an error.
- `def f : IOError | ParseError` — every member is an error, so `!` could never
  produce a value. Also an error. If a function genuinely never succeeds, its
  return type is `NoReturn`.

#### III.1.2 The propagation operator — **PROPOSED**

For `expr : T | E` where `E : Error`:

- if the value is a non-error member, `expr!` evaluates to it;
- if it is an error member, `expr!` returns it from the enclosing function.

The enclosing function's return type must already include `E`. There is no
implicit widening.

```
pub def load(path : String) : Config | IOError | ParseError
  text = read(path)!          # read  : String | IOError
  parse(text)!                # parse : Config | ParseError
end
```

**Narrowing.** `expr!` removes *all* error members, so the result type is the
union of what remains. This falls out of unions rather than being bolted on:

```
find(id)         # => User | Admin | NotFound | DBError
find(id)!        # => User | Admin
```

That is a real payoff of choosing unions over a two-parameter `Result`, which
would have forced the success side into a single type or a nested tuple.

**Error sets are just aliases**, so wide signatures stay readable:

```
pub alias LoadError = IOError | ParseError
pub def load(path : String) : Config | LoadError
```

**Inside blocks**, `!` returns from the enclosing *method*, matching Crystal's
existing `return`-in-block semantics. `items.map { |x| parse(x)! }` therefore
abandons the whole method on the first failure. Consistent, and worth stating
because the alternative reading is defensible.

#### III.1.3 Handling — **SETTLED**

Nothing new is required. Exhaustive `case`/`in` over a union already exists and
already checks totality:

```
case load(path)
in Config     then serve(it)
in IOError    then log_missing(it)
in ParseError then log_invalid(it)
end
```

Adding a new error member to `load` turns every incomplete `case` on it into a
compile error. This is the main ergonomic argument for the whole approach and it
costs nothing to build.

Two conveniences in the prelude for the cases where matching is overkill:

```
port = read_port().or(8080)     # value, or a default
port = read_port().or_panic     # value, or panic — the `unwrap` of this design
```

These are compiler-known on error unions rather than ordinary trait methods.
They have to be: by II.1 an ordinary method call on `Int32 | ConfigError` would
require *both* members to implement it, which is precisely the thing being
avoided here.

#### III.1.4 Panics, and cleanup — **PROPOSED**

Panics are for bugs, not control flow: index out of range, division by zero,
a violated invariant. They unwind and are catchable **only at task boundaries**,
so a panicking fiber cannot die silently.

Because errors are values returned early, `begin`/`ensure` no longer covers
cleanup properly. Replace it with `defer`, which runs on normal return, on `!`
propagation, and on panic unwind:

```
pub def with_file(path : String) : String | IOError
  f = File.open(path)!
  defer f.close
  f.read_all()!
end
```

#### III.1.5 Nil is not an error — **SETTLED**

`T?` is `T | Nil`, and `Nil` does not implement `Error`. Absence and failure stay
distinct, as they are in Crystal today: `T?` for "not there", error unions for
"tried and failed". Existing flow typing (`if x = maybe_get`) handles nil, and
`!` does not touch it.

**OPEN:** whether a nil-propagating operator is worth having later. Deliberately
excluded from Draft 0 — one new control-flow operator at a time.

#### III.1.6 Error conversion — **OPEN**

Rust's `?` silently converts error types through `From`. That is convenient and
it is also the mechanism by which Rust error handling became something people
write blog posts to explain.

Draft 0 requires the error type to already be a member of the caller's return
union; conversion is written by hand. Recommend keeping it that way until real
code proves it unbearable.

### III.1.7 The conflict this design creates — **needs your call**

Working through the operator surfaced a problem the earlier draft only gestured
at. It is not cosmetic.

Crystal allows `!` as the final character of a method name — `sort!`, `map!`,
`not_nil!`, `strip!`. Postfix `!` for propagation makes `arr.sort!` **genuinely
ambiguous**: it is either a call to a method named `sort!`, or a call to `sort`
whose error is propagated.

A compiler can resolve it by preferring the method name when one exists. That is
worse than the ambiguity, because it means **adding a `sort!` method to a type
silently changes the meaning of existing `arr.sort!` call sites** from "propagate
the error" to "call the mutating method". Action at a distance, of the exact kind
R-3 was introduced to eliminate.

Three ways out:

**A. Drop `!` from identifiers. Keep `?`. — recommended.**
Adopt Swift's naming convention instead: the mutating form is the plain verb,
the non-mutating form is the participle.

```
arr.sort          # mutates in place
arr.sorted        # returns a new array
arr.reverse       # mutates
arr.reversed      # returns new
```

`?` stays legal in identifiers (`empty?`, `nil?`) and never collides, because
nilable types use `?` in *type* position, not after an expression. The loss is
one naming convention; the gain is an unambiguous operator and, arguably, a
better convention — `sorted` says what it returns, `sort!` only says it is
dangerous.

**B. Keep `!` identifiers, disambiguate by lookup.** Cheapest to adopt, and
carries the silent-meaning-change footgun described above. Not recommended.

**C. Prefix keyword: `try read(path)`.** No ambiguity, reads well in isolation,
composes badly. Compare chaining:

```
read(path)!.strip.parse!          # A
(try read(path)).strip |> try     # C, roughly — parens required at every step
```

Postfix wins wherever a fallible call is part of a larger expression, which is
most of the time.

**Recommendation: A.** It costs one Ruby convention and buys an operator with no
special cases. But this is a taste decision about the language's surface, so it
is yours.

#### III.1.8 Worked comparison

Crystal today:

```crystal
def load_config(path : String) : Config
  text = File.read(path)          # raises IO::Error
  Config.from_yaml(text)          # raises YAML::ParseException
end

begin
  config = load_config("app.yml")
rescue ex : IO::Error
  STDERR.puts "missing: #{ex.message}"
  exit 1
rescue ex : YAML::ParseException
  STDERR.puts "invalid: #{ex.message}"
  exit 1
end
```

iyi:

```
pub def load_config(path : String) : Config | IOError | ParseError
  text = fs.read(path)!
  Config.from_yaml(text)!
end

case load_config("app.yml")
in Config     then run(it)
in IOError    then abort("missing: #{it.message}")
in ParseError then abort("invalid: #{it.message}")
end
```

The bodies are the same length. The signature now states what can go wrong, and
the `case` is checked for totality — adding a third failure mode to
`load_config` breaks this call site at compile time instead of at runtime.

**The honest cost.** Every fallible function's signature grows, and every caller
either handles or propagates. In a deep call chain that is real friction, and it
is the friction Go is criticised for. `!` and error aliases blunt it; they do not
remove it. This remains the largest departure from Ruby feel in the design.

### III.2 Garbage collector — **SETTLED by II.5**

No longer an open question. R-4 forces a precise collector; recommendation is
precise, generational, non-moving for Draft 0.

### III.3 `method_missing` — **PROPOSED: cut it**

It requires an open method set, which R-3 closes by construction.

Grounded rather than asserted: in the Crystal standard library `method_missing`
appears **once**, as the hook definition in `object.cr`. **Kemal does not use it
at all.** Meanwhile `responds_to?` — the static alternative — appears across 34
files. The dynamic escape hatch is close to unused; the static one is what
people actually reach for.

Cut it. Keep compile-time `responds_to?`.

---

## Part IV — Not yet specified

Named honestly, so nobody mistakes this draft for complete.

1. **Export metadata format.** The on-disk contract for `.iyimod`. Everything in
   R-1 depends on it and none of it is designed.
2. **Trait generics and associated types.** `trait Into(T)`, `trait Iterator` with
   an element type. Unavoidable for a real stdlib; not addressed here.
3. **Trait default methods.** Whether a trait may supply a body. Affects
   whether traits can carry the Enumerable-style surface that makes Crystal
   pleasant.
4. **Module initialisation order.** Kemal registers routes as a side effect of
   top-level calls. Legal, but the ordering guarantees across a module DAG need
   stating. Go's `init()` is the reference.
5. **Concurrency semantics.** `Channel(T)` and `Fiber` carry over from Crystal,
   but their interaction with module-level mutable state — which the Kemal port
   flagged as a smell worth fixing — is unspecified.
6. **Macro cost.** Still unmeasured. The one gap in the measurement record; the
   attempt to isolate it was invalid because the test program never called the
   generated methods.
7. **Stdlib naming convention.** If III.1.7(A) is accepted, `!` leaves
   identifiers and the mutating/non-mutating pair becomes `sort` / `sorted`.
   That is a convention the entire standard library has to be designed around
   from the first commit, so it needs deciding before any stdlib code exists —
   not after.
8. **`defer` semantics.** Ordering of multiple `defer`s in a scope, and whether
   a `defer` may itself propagate with `!`. Go's answers (LIFO; no) are probably
   right but are not automatic here.

---

## Appendix — What measurement settled

For traceability, since several rules here rest on numbers rather than taste.

| Claim | Evidence |
|---|---|
| Separate compilation is the main prize | 1000 typed functions cost +0.08 s; ~95% of non-LLVM work is fixed prelude tax |
| Open classes are the blocker | 77 of 484 types reopened across module boundaries; `String` by five modules |
| Traits are a viable replacement | Kemal router ports at +4% code size, structure intact |
| `using` is required, not optional | Kemal's DSL is unwritable without it |
| Dictionaries pay off at compile time | 46.6% of instantiations collapse (compiler), 47.7% (app-shaped code) |
| Dictionaries cost ~3–4 cycles per call | 17.5× on a vectorisable loop, 1.21× where neither side vectorises, 1.00× with real work per element |
| `macro_run` must go | 21% of a cold build from one call site |
| `method_missing` is safe to cut | one occurrence in stdlib, zero in Kemal |

## Appendix B — Decisions awaiting your call

| # | Decision | Recommendation |
|---|---|---|
| 1 | Errors as unions at all (III.1) | yes — biggest departure from Ruby feel, so it is a taste call |
| 2 | `!` in identifiers vs `!` as propagation (III.1.7) | drop `!` from identifiers, adopt `sort`/`sorted` |
| 3 | Implicit error conversion (III.1.6) | no, for Draft 0 |
| 4 | Nil-propagation operator (III.1.5) | not in Draft 0 |
| 5 | `pub using` re-export (II.3) | no, for Draft 0 |
