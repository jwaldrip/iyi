# iyi Language Specification — Draft 0

**Status: draft for discussion. Parts of it are built — each section says which,
and a heading that does not say so is a heading to distrust.** What 0.1.0 needs
of it is scoped below Part I.

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

## 0.1.0 — what the first release has to prove

Everything below this line is design. This section is scope, and it is here
because the rest of the document is easier to read once it is known which parts
of it the first release is allowed to need.

**0.1.0 is not a usable language.** It is the smallest artifact that lets
somebody who did not write it check the central claim and find it false. Nobody
will write production code with it, there will be no standard library worth the
name, and it will not be self-hosted. Go's first public release was the same
shape.

**The claim under test** is compile speed. The type system is the means, not the
product: open classes go so that a module can be compiled against its
dependencies' metadata instead of their bodies (R-1, R-3), and that is what
makes a build incremental. A release that ships the type system without the
speed has shipped the cost and none of the benefit.

### In scope

**1. `.iyimod`, end to end (IV.1). Front end done; object code started.** Not
negotiable. R-1 is the rule the rest of the document is built on, and without
the artifact everything here is a design document. The container, the `Header`,
`Imports` and `Exports` sections, `--emit-iyimod` and `mod dump` are built, and
`--use-iyimod` now compiles an imported module from its artifact: seven of the
eight samples compile with the imported module's source **deleted**.

`ObjectCode` carries a module's own machine code, and **a program built from a
module's artifact with the module's source deleted now runs** — the first thing
here that produces a program rather than a typecheck. `modules.iyi` builds,
links and runs from its two modules' artifacts with both sources deleted, and
prints what it printed from source.

Of the five samples that import anything, **four** do — `modules`, `immutable`
(a generic type, a 575-line trait with an associated type, a generic impl),
`collections` (the trait implemented by a type the artifact's module has never
heard of) and `init_order` (III.5's ordering, line for line). The fifth,
`webapp`, is refused a step earlier by R-2 and has been since before this
section existed. IV.1g measures all of it.

**2. The passes that still walk the prelude stop walking it (IV.1d).** The
artifact alone leaves 0.47 s, of which class-var initializers and `main` are
90%, because six of the eleven semantic passes re-walk the prelude AST whatever
put it there. 0.47 s beats Crystal and does not beat Go. This item is the
headline number, not a refinement of it.

**3. A deliberately tiny prelude, written in iyi. Done — 1,053 lines,
primitives included.** Not a standard library: integers, booleans, a string,
one sequence, one dictionary, `puts`. **Its scope is set by what the samples
call and by nothing else** — a method enters the prelude because an existing
sample needs it, never because it belongs there.

The ceiling was not a guess. Crystal's own 0.1.0 shipped 8,161 lines of
library, of which the core — `object`, `nil`, `bool`, `char`, `int`, `float`,
`number`, `string`, `array`, `hash`, `range`, `enumerable`, `comparable`, `io`,
`pointer`, `exception`, `raise`, `main`, `prelude` — is **3,551 lines**. The
rest is `json`, `yaml`, `http`, `option_parser`: libraries, not a prelude.
3,551 lines was the number to stay under, measured in the same language family
and for the same purpose. `src/iyi/` came in at 833, and **all eight samples
run on it with output identical to what they print under Crystal's prelude**,
which is the acceptance test: the samples are the documentation, so a prelude
that changed what they printed would have changed what the documentation says.
A `.iyi` entry file gets it by default; `--prelude` still wins, and a `.cr`
file is untouched.

| | measured |
|---|---|
| front end, `hello.iyi` | 1.41 s → **0.13 s** |
| whole build, `hello.iyi` | 2.10 s → **0.32 s** |
| whole build, `webapp.iyi` | 2.17 s → **0.36 s** |

**And then the same rule applied one level down.** With Crystal's prelude gone,
0.11 s of the remaining 0.17 s front end was `src/primitives.cr` — not its 581
lines but its shape: twelve numeric types crossed with each other is 2,580
`@[Primitive]` definitions macro-expanded on every build. Measured by deleting
the block and building again, which took the front end to 0.02 s.

So iyi has its own. **`src/iyi/primitives.iyi` crosses five types** — `Int32`,
`Int64`, `UInt8`, `UInt64`, `Float64`: the default integer, the one a byte
count grows into, the byte, the one an address and a size are, and a float.
That is 445 definitions, and it took the front end to 0.07 s. `Int8`, `Int16`,
`Int128` and the unsigned middle exist as types and have no arithmetic;
`1_i8 + 1_i8` is an undefined method. **This is a language-visible decision,
not a library one** — it is the same rule as the rest of the prelude (a thing
enters because a sample writes it) applied to the one file where the cost is
quadratic. What it does not decide is implicit promotion: the five types cross
each other exactly as Crystal's twelve do, so `1 + 1_i64` still works. Whether
iyi keeps that or takes Go's line and demands an explicit conversion is open,
and cheaper to answer now that the block is small enough to read.

Three decisions made it that small, and each is a thing 0.1.0 does not have
rather than a trick. **There is no `IO`**: `puts` writes to fd 1 and `to_s`
returns a `String`, which removes buffering, encodings and the class hierarchy
under them — the largest single saving against Crystal's core. **`raise` is a
panic** (III.1.4): it prints and exits, so there is no unwinder, no personality
function and no exception hierarchy, and the three `__crystal_*` symbols that a
program with an `ensure` in it must link are stubs that say they cannot be
reached. **Strings are ASCII** wherever a method has to look inside one —
`upcase`, `starts_with?` — though `size` decodes UTF-8 properly, because a
sample counts the characters of a word with an accent in it.

What it is not: no `Float64#to_s`, no `Range`, no `Set`, no formatting, no
`Comparable`, no deletion from a `Hash`, and `sort` is an insertion sort
because the samples sort five elements. Each of those is absent because no
sample asked, which is the rule doing its job rather than a list of regrets.

**4. IV.6 #6, module naming. Done.** A module is declared `app/greeter` and
reached `App::Greeter`. This appears in every line of user code and could not be
changed once there was user code, so it was settled first. The mismatch stays
and is made reversible instead: a path segment is `[a-z][a-z0-9]*` with single
`_` between groups, so path and type name determine each other. "Lowercase
snake_case" turned out not to be enough — `v_1` and `v1` both give `V1`.

**5. A benchmark that produces the claim, and a check that fails until it
holds. Built.** `bench/` already priced macros and `Share`; build speed was the
one number the project exists for and the one with no committed harness.
`bench/build_speed.py` is it, and its first run is below. Its corpus is one
program, because `hello` is the only pair where "the equivalent Go program" is
unambiguous and because iyi has no other program to offer — which makes growing
that corpus a dependency of this item on item 3, not a nicety.

### Out of scope, stated so it is not argued twice

III.4 in its entirety — structured concurrency is specified and it is not on
the critical path of the claim. III.5 rule 5's measurement. Cross-version
`.iyimod` compatibility (IV.5 already says this). A package manager. A standard
library. Self-hosting: the compiler is 95,010 lines and iyi's own library is
722, so this is not a near thing and pretending otherwise sets the wrong
priorities. Of the calls still open in Appendix B, only #1 is a taste decision
that would change what 0.1.0 looks like, and deferring it costs nothing.

### Done is a number

1. `bench/build_speed` prints one table, measured on one machine: iyi cold, iyi
   warm, and `go build` on the equivalent program. **The Go column is measured
   there, not quoted from anywhere** — this document has no Go timing in it and
   is not entitled to one until the bench runs.
2. The front end compiles `hello.iyi` in **0.05 s or less**. This is not an
   aspiration: IV.1a already ran a front end that never walks the prelude at
   0.049 s, and it emitted an object with an identical symbol table. 0.1.0's job
   is to make that configuration the ordinary one rather than an experiment.
   **Met: 0.039 s.** Not by the route IV.1a took — the prelude is small enough
   now that there is little left to cache — and two of the three things that
   closed the gap were the prelude and its primitives. The third was the
   instrument; see below.
3. The end-to-end `crystal build` time is published in the same table even
   though LLVM and the linker dominate it, so that the claim cannot quietly
   become a front-end-only claim.
4. The check for (2) is the bench's own exit status, not a spec. The release is
   a command that passes, not a judgement call — the same standard as the rest
   of this document. **Built:** `python3 bench/build_speed.py` exits non-zero
   while the target is unmet, and names which scope item closes the gap. It is
   deliberately not a `spec/compiler/…` example: one permanently red assertion
   in that suite would cost it the only thing it is good for, which is that a
   failure there means something broke.

**The first run, recorded because a bench with no baseline is a script.** On one
machine, best of three, seconds:

| program | stage | cold | warm |
|---|---|---|---|
| `hello.iyi` | front end (`--no-codegen`) | 1.32 | — |
| `hello.iyi` | end to end | 2.20 | 1.96 |
| `hello.go` | `go build` | 1.98 | 0.18 |
| `webapp.iyi` | front end, iyi only | 1.31 | — |

Three things fall out of it, and none were stated before it ran.

**The fight is the warm build, and it is 11× not 3×.** Cold, the two are level
— 2.20 against 1.98, because Go is compiling its own dependencies too. Warm,
Go drops to 0.18 and iyi to 1.96, because Crystal's cache only holds codegen
and the front end is redone in full every time. Warm rebuild is what a person
actually waits for, so **11× is the real gap**, and it is almost exactly the
front end: item 1 plus item 2 are worth 1.32 s of the 1.78 s difference.

**Being level when cold is not a consolation, it is a warning.** It means iyi's
cold build is already as expensive as compiling Go's stdlib from source, on a
program that prints one line.

**`webapp.iyi` costs the same as `hello.iyi`**, 1.31 against 1.32. IV.1d found
this on the previous instrument and it still holds on this one: user code is
nearly free and the fixed prelude cost is the whole bill. It is why the target
is set on a one-line program rather than a large one.

**The second run, after item 3.** Same machine, same command, with iyi's own
prelude (833 lines) in place of Crystal's 107,719:

| program | stage | cold | warm |
|---|---|---|---|
| `hello.iyi` | front end (`--no-codegen`) | **0.17** | — |
| `hello.iyi` | end to end | **0.38** | **0.37** |
| `hello.go` | `go build` | 2.54 | 0.16 |
| `webapp.iyi` | front end, iyi only | **0.18** | — |

**The 11× warm gap is 2.3×**, and it went there by deleting a dependency
rather than by making anything faster: nothing in the compiler changed for this
row. The front end is 7.8× off its own previous number and 3× over the target
rather than 26×.

**Cold, iyi is now 6.7× faster than Go**, 0.38 against 2.54, because Go cold
compiles its standard library and iyi cold compiles 833 lines. That reverses
the first run's warning and replaces it with a smaller one: the comparison is
only fair while iyi's library is this small, and it stops being flattering the
moment iyi has one worth the name.

**What is left is the same shape one order down.** 0.17 s of front end is 833
lines of prelude analysed from source on every build — which is exactly the
thing `.iyimod` removes, and the prelude is now a module small enough to be
one. Item 1 and item 2 are still what closes the last 3×.

**The third run, and the target is met.** Two changes, one of them to the
instrument:

| program | stage | cold | warm |
|---|---|---|---|
| `hello.iyi` | front end (`--no-codegen`) | **0.04** | — |
| `hello.iyi` | end to end | **0.25** | **0.25** |
| `hello.go` | `go build` | 2.37 | 0.14 |
| `webapp.iyi` | front end, iyi only | **0.05** | — |

  measured 0.039 s against a 0.05 s target — **MET**.

The first change was iyi's own `primitives.iyi`, above: 0.17 s → 0.07 s. The
second was the instrument, and it has to be said plainly rather than banked.
**The bench used to time `bin/crystal`**, a POSIX-sh wrapper that resolves
symlinks with recursive shell functions, shells out to `uname` and `readlink`,
prints which compiler it found, and then `exec`s the binary. It costs **30 ms**.
`go build` is timed as a bare binary, so half of what was being compared was
this repository's development ergonomics. The bench now asks the wrapper once
for the two paths it knows and times the compiler: 0.07 s → 0.039 s.

**So the honest reading is that the target is met by the compiler and not yet
by `bin/crystal`**, which is still 0.066 s and is what a person in this
checkout actually types. Shipping a binary rather than a shell script is a
packaging job, not a compiler one, and it is not what this document is about —
but it is 45% of the number until it is done.

**What is left of the front end.** Of 0.039 s: about 0.020 s is the top-level
pass over 1,053 lines of prelude and primitives, about 0.008 s is every other
semantic pass together, and the rest is process startup. Item 1's artifact
would carry the first term and item 2 addresses a term that is now 8 ms. The
gap that made this project has closed to the point where the remaining costs
are the ones every compiler has.

### What Crystal's own 0.1.0 looked like

The scope above was drawn before checking it against the one release most
comparable to it — the same language family, the same first-release question.
Checking it moved two things and left the shape alone.

| | Crystal 0.1.0 (2014-06-18) | iyi today |
|---|---|---|
| Compiler | 24,984 lines, **written in Crystal** | 95,010 lines, Crystal, forked |
| Library | 8,161 lines (3,551 of it core) | 1,053 prelude + 722 in samples |
| Specs | 21,146 lines | ~3,400 for iyi |
| Samples | 24 **programs** | 8 **explanations** |
| History | 3,165 commits over 21 months | 75 |
| Own status line | *"pre-alpha: we are still designing the language"* | design largely settled, building not started |

**It shipped admitting the language was undesigned.** No binaries, clone and
run `bin/crystal --setup`, OSX and 32/64-bit Linux. That is permission rather
than a rebuke: the scope above is *more* conservative than the release it is
being measured against, and iyi is further along in design at this point than
Crystal was at its first release. It is behind on building and ahead on
deciding.

**Its samples were programs.** mandelbrot, binary-trees, brainfuck,
`http_server`, sudoku, a red-black tree, n-bodies, SDL and Cocoa bindings. iyi's
samples are better in one respect — every claim in them is compiled, which
Crystal's were not — and they have a gap Crystal's did not: **no iyi program
does any work.** A build-speed claim needs programs to build, and the benchmark
in item 5 therefore starts with almost nothing to measure. Growing that corpus
is a dependency of item 5, not a nicety, and it is bounded by item 3: a program
can only be written once the prelude carries it.

**And self-hosting was already behind it.** Crystal's compiler was written in
Crystal before 0.1.0, at 24,984 lines against an 8,161-line library. That is
the cheapest such a move is ever going to be, and the cost only rises. See
Appendix B #10 — the fork means iyi has already passed that point, and this
document has been silent about it.

### The item that decides the schedule

Item 3. "Tiny prelude" sounds small and is not: writing a string and a
dictionary under iyi's own rules — no open classes, `Share`, `sorted` — is the
first real library ever designed against them, and the whole of the evidence
that this is possible is one ported `Enumerable` and 722 lines of samples. The
bound is the rule stated above: the samples decide what goes in. If that bound
slips, 0.1.0 becomes a standard-library project and the claim goes unmeasured
for a year.

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

### II.3 `using` × everything — **BUILT, one sub-question open**

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

**Enforced.** `pub` is what a module's surface is, and both halves are closed:
`using` reaches only exported names — the selective form reports at the
directive which of the names it asked for the module does not export — and a
qualified `App::Greeter.helper` or `App::Greeter::Closed` is refused too.

The second half is not decoration. `.iyimod` carries a module's exports and
nothing else (IV.2), so if another module could reach an unmarked name, that
metadata would not be enough to compile against and R-1 would not hold.

Only a `module app/greeter` compilation unit has a surface, and only its own
body carries it: a `def` inside a `pub trait` or a `pub struct` belongs to the
trait or the struct. `Enumerable#to_a` writes no `pub` and stays callable on
every implementer. A Crystal module never wrote `pub` and is untouched.

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
and `macro_run` — the last of which costs a fixed **+7.4 s per distinct script**
on a cold build, remeasured in II.10.

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

### II.6 Traits × the standard library — **SETTLED by porting `Enumerable`**

`Enumerable` is the load-bearing abstraction of Crystal's stdlib: 2,350 lines,
**130 methods built on a single `abstract def each`**, included by 17 types.
`Comparable` reaches 21 more. If traits cannot express that shape, the library
cannot be written in Crystal's idiom and the ergonomics half of the pitch fails.

It ports. But it required three things Draft 0 did not have, and exposed one
genuine conflict.

**It now ports in the compiler, not on paper.**
`samples/iyi/std/enumerable.iyi` carries **57 of Crystal's 71 distinct method
names** (58 defs against Crystal's 117, which counts overloads), all written
against one `abstract def each`. `samples/iyi/collections.iyi` implements it for
two types that answer `Elem` differently and calls every one of them — a default
method that is never called is never typed, so a trait that merely compiles
proves nothing. What is left out is listed at the foot of the port, and is
mostly the nilable-variant family (`minmax?`, `max_by?`) and methods that
destructure the element (`to_h`, `chunks`). It needed the
three things below and nothing else. Three findings came out of the port that
this section had wrong or had not reached:

- **The block must not be captured.** The sketch below writes
  `abstract def each(&block : Elem -> Nil)`. That form captures the block into
  a `Proc`, and a captured block cannot `return` from the enclosing method —
  which removes early exit from `find`, `any?`, `all?`, `none?`, `first`,
  `take`, `take_while`, `empty?`, `index` and `find_value`. It has to be typed
  without being captured, `& : Elem -> Nil`, and yielded. Corrected below.
- **Dropping `!` made the library more consistent.** Crystal spells two of
  these `find!` and `index!`, against its own `max?`/`max` and `first?`/`first`
  convention, only because plain `find` was already taken by the nilable one.
  With `!` gone (III.1.7) the port uses `find?`/`find` and `index?`/`index`
  throughout. The naming decision paid here rather than cost.
- **A trait needs to require class-level methods, and now can.** `sum` and
  `product` with no argument need an additive and a multiplicative identity,
  and an identity belongs to the type: an empty collection has no element to
  ask. So `Num` declares `abstract def self.zero : self`, an impl answers it
  with `def self.zero`, and `sum` reaches it as `Elem.zero` through the
  associated type. The requirement is checked at the impl like every other,
  and reported as `self.zero` — what has to be written to fix it. It stays
  refused outside a trait, where an abstract class method would oblige nobody:
  only a trait has implementers whose class methods anything checks.

  This is checked separately from the instance requirements, because `include`
  carries instance methods only. The trait's metaclass defs never reach the
  target's, so there is nothing for the impl to have inherited — it has to have
  written them.

Finding 6 below is realised too: `zip` is `forall O : Enumerable`, and `O::Elem`
names what the other collection yields without the caller stating it.

**1. Traits need associated types as well as parameters.**

```
pub trait Enumerable
  type Elem                                     # an output of the impl
  abstract def each(& : Elem -> Nil) : Nil      # required, and not captured
  def to_a : Array(Elem)                        # default, has a body
    # ...
  end
end
```

**`abstract def` marks a requirement, and this was corrected by writing the
parser.** The first draft used a bare `def each(...) : Nil` with no body. That is
ambiguous in a language with no statement terminator: after the signature, the
parser cannot tell a requirement from a default whose body starts on the next
line without unbounded lookahead. Rust avoids this with `;`. `abstract` is
already a Crystal keyword meaning exactly this, so it costs nothing and reads as
expected.

A collection iterates one way, so the element type is not something the caller
picks — making it a parameter would leave `arr.map` ambiguous about which impl
it means. But parameters are still needed where several impls are the whole
point (`Into(T)`, `From(T)`). **Both forms exist.** Draft 0 assumed only
parameters.

**Both are built.** An impl answers an associated type in its body, and names a
trait's parameters where it names the trait:

```
impl Container for Names          impl Into(String) for User
  type Elem = String                def into : String
  def first : String                  "u"
    "ada"                           end
  end                             end
end
```

Both are carried as type vars of the trait — what a trait's signatures and
default bodies need from them is identical, and an included generic module is
already how Crystal resolves such a name. They differ in exactly one checked
rule, which is the whole reason the distinction exists: **a trait that declares
associated types can be implemented only once for a given type.** A second impl
answering `Elem` differently would make a call on that type ambiguous, which is
the cost that ruled out making the element type a parameter. A trait with
parameters has no such rule, because several impls are the point of it.

One gap the implementation found, and it is on the parameter side: two impls of
the same parameterised trait for one type **collide when their methods take the
same arguments**. `impl Into(String) for U` and `impl Into(Int32) for U` both
define `into`, and the second silently wins. That is the shape parameters exist
for, so it needs an answer; Rust's is to select the impl from the type the call
site expects, which this design does not yet have anywhere else.

**2. Default methods need their own type parameters.**

```
def map(&block : Elem -> U) : Array(U) forall U
```

`U` belongs to the method, not the trait. Unavoidable — `map`, `flat_map`,
`group_by`, `min_by` and `to_a(&)` all need it.

**3. Default methods need conditional bounds.**

```
def max  : Elem            where Elem : Comparable
def sum  : Elem            where Elem : Numeric
def tally : Hash(Elem, Int32) where Elem : Hashable
```

About a quarter of `Enumerable` is only valid for some element types. Crystal
duck-types these and fails at instantiation with a confusing message; a closed
method set forces the bound to be written. More work for the library author, a
much better error for the caller.

**Built.** `where` bounds a name the method did not introduce, which is what
separates it from `forall`: `forall` introduces a name and may bound it, `where`
bounds an associated type the enclosing trait already introduced. The check runs
where the call is matched, because by then the associated type is a type, and it
reports `Int32 does not implement Comparable, required by `where Elem :
Comparable` in `max``. The unbounded methods of the same trait stay available
whatever the element type is; only the bounded one is withheld.

**3a. A trait needs to require another trait.** `Comparable` reaching 21 more
methods is only sound if an implementer of the trait that uses them has them.

```
trait Ord : Cmp
  def beats(other : self) : Bool
    cmp(other) > 0        # Ord never declared `cmp`
  end
end
```

**A requirement, not an inclusion.** Were `Ord` to include `Cmp`, every
implementer of `Ord` would satisfy `Cmp` with no `impl Cmp for` it anywhere —
the open-class hole R-3 exists to close. So `impl Ord for X` is refused unless
an `impl Cmp for X` already exists, and `Ord`'s default bodies still reach
`cmp` because a module's body resolves against the type it is included in.
Transitivity is free: if `Cmp` required `Show`, the `impl Cmp for X` this one
insists on was checked the same way.

The price is that impls have to be written in dependency order. The check needs
this impl and the trait's declaration and nothing else, which is what R-1 asks
of it, and nothing has run that would know about an impl written later.

**4. The conflict: where default bodies are compiled.**

R-1 says compiling a module reads only export metadata, never bodies. But a
default method's body must be compiled for each implementing type, and the
implementer is in another module. This is the Go/Rust fork a second time:

- **(a)** Stencil the body once per GC shape in the trait's module, reaching
  element operations through a dictionary. Pure R-1, cheap to compile — and it
  pays the cost measured at **4.3× on reference field access**, which is exactly
  the shape of `arr.map(&.name)`, the most idiomatic line in Crystal.
- **(b)** Ship default bodies in export metadata so the implementing module
  monomorphises them. Fast at runtime; precisely why Rust compiles slowly.

**Resolution: (a) by default, `@[Monomorphize]` opting a method into (b).** The
hot handful — `each`, `map`, `select`, `reduce` — are marked in the stdlib; the
other ~120 stay stencilled.

The price is real and belongs on the record: **the library author now makes a
per-method performance decision and has to get it right.** Crystal's author
never faced that choice, because everything monomorphises. This is the clearest
place where iyi asks the stdlib to absorb complexity so that user builds stay
fast.

**5. Dictionaries carry a type descriptor, not just a pointer map.**
`select(type : U.class)` filters by runtime type, so dictionaries need type
identity. II.5 had claimed only pointer maps; Go's dictionaries carry both.

**6. One simplification found.** Crystal's
`zip(*others : Indexable | Iterable | Iterator)` is duck typing left over from
having no traits. In iyi it is `forall O : Enumerable`. A union-of-traits bound
would mean "implements at least one of", which no body could rely on — it should
not exist in the language.

### II.7 Generic impls — **SETTLED**

`impl Enumerable for Array(T) forall T`. Four decisions, each taken from the
language that already paid for the mistake.

**1. The binder is required (Rust).** `impl Show for Box(T)` with no `forall T`
is refused. Without the binder, whether `T` is a new parameter or a type
already in scope depends on what happens to be imported — so a library could
change the meaning of a consumer's impl by adding an export. Rust requires
`impl<T>` for exactly this reason. The cost is four characters; the error names
them.

**2. Parameter names are the impl's own, bound positionally (Rust and Java,
not Crystal).** `impl Show for Pair(X, Y) forall X, Y` works on a `Pair(A, B)`.
Crystal requires a reopened generic to repeat the declared names, which leaks a
type's private naming into every impl of it. An impl states arity, not
vocabulary.

**3. A bound is a trait, and nothing else (Go).** `forall T : Show`. There is no
separate constraint language: what you can bound by is what you can implement.
This matters more here than in Go, because under R-4 a bound is not only a
check — it is what gets passed, as the dictionary.

**4. No specialisation and no blanket impls (Java's position; Rust's unfinished
business).**

- `impl Show for Box(Int32)` alongside `impl Show for Box(T) forall T` is
  refused. Overlapping impls need a rule for which one wins, and that rule has
  to stay sound when the two live in different modules compiled separately.
  Rust has wanted specialisation for a decade and it is still unstable. Java
  cannot express it at all. Refusing it is what keeps `Box(T)`'s method set
  knowable without knowing `T` — the same property R-3 exists to protect.
- `impl Show for T forall T : Debug` — a blanket impl — is refused for the same
  reason open classes are: it lets a distant module add methods to every type.

**What it costs.** Nothing extra at build time. Under R-4 an impl on a generic
type is compiled once per GC shape, not once per instantiation, so a generic
impl is one body and not N.

**A bound on a method and a bound on an impl are two different features.** The
draft treated `forall T : Show` as one thing. Implementing it showed the two
places it can be written have almost nothing in common:

| | What it means | Cost |
|---|---|---|
| `def add_route(&block : Ctx -> B) forall B : IntoBody` | The method exists either way. When `B` binds to a concrete type, check that the type implements the trait. | One check at the call site. **Built.** |
| `impl Show for Box(T) forall T : Show` | `Box(Int32)` implements `Show` only if `Int32` does — a **conditional** impl, checked where the type is instantiated rather than where the impl is written, and interacting with coherence. | A separate mechanism. **Not built.** |

The method form is the one the Kemal router depends on, in both `add_route`
and the macro loop that generates the HTTP verbs, so it was on the critical
path of the design's own acceptance test while being the cheaper of the two.
The error names the type, the variable and the method:

```
Error: Int32 does not implement App::Router::IntoBody, required by `B` in `add_route`
```

It is reported as an error rather than as a failed overload match. Under R-3 a
type's method set is closed, so "`Int32` does not implement `IntoBody`" is the
true reason a call is rejected, and Crystal's "no overload matches" would bury
it. This is also where II.6 finding 6 lands: `zip(*others : Indexable |
Iterable | Iterator)` becomes `forall O : Enumerable`.

**A generic impl of a trait with an associated type — II.7 × II.6 — did not
work until something needed it.** `impl Enumerable for List(T) forall T` with
`type Elem = T` reported `undefined constant T`. Both halves were built and
specced; they had simply never been written together, because every impl in the
samples was either generic with a parameterless trait (`Show for Box(T)`) or
associated-typed on a concrete target (`Enumerable for Nums`).

The cause is worth recording, because the obvious fix is the wrong one. An
impl's answer to an associated type becomes an argument of the `include` the
compiler writes, and that argument may name a parameter of the *target* —
`List`'s `T` — which is not in scope where the impl was written. Pushing the
target's scope to find it loses the trait, whose name lives in the impl's own
module, and breaks every `impl Cmp for Int32` in `samples/iyi/std/traits.iyi`.
The parameters have to be passed as **free variables** into a lookup that still
happens in the impl's scope, which is what resolving a superclass from inside a
generic already does. Both names then resolve, each from where it actually
lives.

That a generic collection implementing `Enumerable` is the first program to
need this says something about the order the samples were written in: the
canonical case arrived last.

### II.8 What a trait is, and is not — **SETTLED**

Draft 0 said `impl Trait for Type` and left "trait" undefined. The first
implementation desugared it to a module, which compiled but meant a trait and a
module were the same thing: `include Greet` worked, `using Greet` worked, and
`abstract def` was Crystal's abstract method rather than a requirement of
anything. Writing the checks settled what the word means.

**The distinction is at the declaration and use sites, not in the type
hierarchy.** This is the finding, and it went the opposite way from the
expectation. A trait has to *be* a type — `def render(x : Showable)` is
ordinary iyi, and it dispatches to the impl — and everything that makes that
work is what a module already does: it holds the required and default methods,
an impl registers the implementing type against it, and a call on a
trait-typed receiver resolves through the set of implementers. Rebuilding that
as a separate kind of type would mean reimplementing restriction matching,
union dispatch and codegen to arrive back where it started.

So `TraitType` is a *subclass* of the module type. What it adds is the ability
to refuse four things:

| Written | Refused because |
|---|---|
| `include Greet` / `extend Greet` | A type acquires a trait by having an impl, whose location R-3 can check. `include` has no such rule — it is the open-class hole under a different name. |
| `using Greet` | A trait exports no names to bring into scope. By II.3 rule 1 a trait method is resolved from the receiver, never from a `using`, so the two never meet. |
| `impl SomeModule for X` | A module has no requirements to satisfy and nothing for R-3 to check. Only a trait is implementable. |
| `impl Greet for SomeTrait` | A blanket impl in disguise, refused for the reason II.7 gives. |

The selective form of `using` may still *name* a trait —
`using app/show::{Showable}` uses the module and selects a type from it, which
is II.3 working as specified.

**`abstract def` is a requirement, checked where the impl is written.**
Crystal's abstract-method check reports at the point the type is first *used*,
names the type rather than the impl, and says nothing at all if the type is
never used. The trait reading is different in all three: an impl that does not
satisfy the trait is wrong when it is written, whether or not anything uses it.
The check is local — it needs the trait's declaration and this impl, never a
global pass, which is what R-1 requires of it.

A requirement is satisfied by the method existing on the target, not strictly
by the impl block defining it. A `def show` written on the struct itself lives
in the type's own module, which is exactly where R-3 would let an impl live, so
accepting it opens no coherence hole.

**Not yet built:** associated types (`type Elem`, II.6) are not parsed, and a
trait cannot yet require another trait.

### II.9 The Kemal port, compiled — **SETTLED**

The design named Kemal's router as its acceptance test and reported that it
passed. That port was done **by hand, on paper**. It has now been fed to the
compiler: `samples/iyi/kemal/{router,dsl}.iyi` and `samples/iyi/webapp.iyi`
compile and run.

**Everything ported, and one thing had to be built first.** `record`, the macro
loop over a module-local constant that generates the HTTP verb surface,
`with sub_router yield`, blocks, procs, `alias`, `case` on symbols, nested
records, `Array(Tuple(String, String))` — none needed a language change. The
single feature the port required that did not exist is the method-level trait
bound of II.7, which is how `HTTP::Server::Context -> _` gets a name. That it
sat on the acceptance test's critical path is the argument for having built it
before anything else on the list.

**The runtime coercion is gone, as claimed.** `router.cr:301` runs
`result.is_a?(String) ? result : ""` on every request. In the port that is
`forall B : IntoBody`, checked once:

```
Error: Array(Int32) does not implement Kemal::Router::IntoBody, required by `B` in `get`
```

Kemal cannot say this — it accepts the block and returns an empty body forever.
And a user can now make their own type returnable by implementing the trait,
which Kemal has no way to offer.

**`using` did what II.3 said it would.** `dsl.cr` opens with "Kemal DSL is
defined here and it's baked into global scope." The port exports the same names
and the consumer writes `using kemal/dsl`; `before_all`, `get` and `mount` are
then unqualified in `webapp.iyi`. The Sinatra feel survives without the library
reaching into the program's namespace.

**The singletons went, and nothing forced it.** `Kemal::RouteHandler::INSTANCE`
and its three neighbours are replaced by one application value. Separate
compilation permits module-level state, so this is not a rule doing the work —
but `router.cr:270` carries "may have been cleared between tests" as a live
workaround, and a clean sheet is the moment such a line stops being necessary.

**What this does not establish.** `Context` is a stub, so no HTTP, no stdlib,
and WebSocket/SSE are omitted as they add no construct the routes do not
already exercise. Registration into handlers is replaced by returning the route
table. The earlier "+4% size" figure is therefore neither confirmed nor
refuted here: the ported scope differs, and comparing 142 lines against 173
would be comparing different programs.

### II.10 Macros × compile time — **SETTLED by measurement**

The last gap in the measurement record, and the one the rest of this document
had been quietly worrying about: this design picks a fight over compile speed
(Part IV), and it inherits Crystal's macros. If expansion is expensive, the
thesis is in trouble.

**It is not.** The measurement is `bench/macro_cost.py`, and it says "macro
cost" is three different numbers, only one of which matters.

**(a) A macro that emits a template costs what writing the code costs.** N
methods generated by a `for` loop, against N methods written out, with every one
of them called in both:

| N | via macro | hand-written | ratio |
|---|---|---|---|
| 0 | 0.143 s | 0.143 s | 1.00 |
| 500 | 0.155 s | 0.154 s | 1.00 |
| 1000 | 0.169 s | 0.168 s | 1.00 |
| 2000 | 0.187 s | 0.183 s | 1.02 |
| 4000 | 0.224 s | 0.215 s | 1.05 |

The per-method delta is not monotonic and sits inside the run-to-run spread, so
what this shows is an absence: **interpreting the macro body, emitting source
and re-parsing it does not cost measurably more than parsing the same source.**

**(b) A macro that computes per item costs about 9 µs per method it emits.**
Same comparison, but the macro builds each name with string operations and takes
a branch per item — the shape a real derive macro has:

| N | via macro | hand-written | ratio | per method |
|---|---|---|---|---|
| 250 | 0.155 s | 0.152 s | 1.02 | ~14 µs |
| 1000 | 0.171 s | 0.166 s | 1.03 | ~6 µs |
| 4000 | 0.253 s | 0.218 s | 1.16 | ~9 µs |

Real, and worth the context: the same table's slope says a *method* costs about
18 µs to define and type at all. **The macro that writes the code is cheaper
than the code it writes**, which is not the relationship anyone assumes.

**(c) `macro_run` is the whole problem, and it is worse than recorded.** On a
cold cache, against the same program with the generated code written out:

| | cold build |
|---|---|
| no `macro_run` | 1.44 s |
| one `run` script | 8.86 s |
| two `run` scripts | 15.76 s |
| the same script twice | 8.02 s |

One call site costs **+7.4 s**, which is not a percentage of anything — it is a
fixed nested compile, so expressing it as a share of the build (the appendix's
21%) says more about the build it was compared against than about `macro_run`.
It is memoised per *script*, not per call site: writing `run("x.cr")` twice
costs once. But a second script costs in full, so the price is linear in the
number of distinct generators a program and its dependencies contain — and a
library that uses one imposes it on every consumer's cold build, forever.

**What this settles.** R-5's derive scoping does not need a compile-time
justification, and should stop being offered one: it earns its place through
separate compilation (a macro that can see the whole program cannot be compiled
against export metadata alone), not through speed. The thing to police is
`macro_run`, which II.2's list already proposed cutting — now with a number that
does not depend on what it was measured against.

**Two notes on method**, both learned by getting it wrong first:

- **The generated methods must be called.** The earlier attempt at this
  measurement was invalid for exactly this reason: methods nobody calls are
  never typed, so it measured a macro producing dead code.
- **The prelude has to go, and the cache with it.** Against the real prelude the
  fixed ~1.4 s tax (IV.1a) is larger than the effect and the delta is pure
  noise — the first run of (a) reported the macro version as *faster*, twice.
  And Crystal caches the compiled `run` script, so without a fresh
  `CRYSTAL_CACHE_DIR` every build after the first reports `macro_run` as free.
  The 8 s cost was visible only as an outlier in the spread.

---

## Part III — Open questions, with recommendations

### III.1 Errors — **DECIDED (Appendix B #1: yes), built except III.1.4**

Errors are ordinary union members. No `Result` wrapper, no exception hierarchy,
no new type machinery — unions already exist and already carry a type id.

```
pub def read(path : String) : String | IOError
```

#### III.1.1 What makes a member an error — **BUILT**

A prelude marker trait:

```
pub trait Error
  def message : String
end
```

A union member is an *error member* if its type implements `Error`. This needs
no new syntax and composes with II.1: `IOError` is a normal type that happens to
implement a normal trait.

**Built.** `Error` is created by the compiler rather than declared in the
prelude, because the compiler has to recognise this exact trait — `!`, `.or` and
`.or_panic` all ask whether a member implements it — and a name the prelude
happened to define could be shadowed or replaced. Nothing else about it is
special: a module writes `impl Error for IOError` like any other impl, and the
`message` requirement is checked like any other.

The type side needed nothing else. Error unions are ordinary unions, and III.1.3
is already true: dropping a branch from a `case` over one is reported as `case is
not exhaustive`. `T?` is untouched, since `Nil` does not implement `Error`.

Two things the build found, both since closed:

- **`it` was not bound in a `case` branch — now it is.** The examples in this
  section write `in IOError then log(it)`, and `case` has learned to bind the
  value it is matching. The binding is an ordinary assignment the expander
  writes into each branch, so `it` picks up the narrowing that branch already
  did: in the `IOError` branch it *is* an `IOError`, not the whole union. Three
  consequences follow from it being an assignment rather than new machinery:
  `it` outlives the `case` exactly the way a variable assigned inside an `if`
  does; a nested `case` shadows the outer one's `it`; and `it` is a name an iyi
  program should not use for anything else. A `case` over a tuple subject binds
  nothing, since there is no single value to name, and a Crystal file is
  untouched.
- **The orphan rule was vacuous for a top-level trait — now it holds.** `Error`
  has no module, and coherence is satisfied by being inside the trait's module
  *or* the type's; where the trait's module was taken to be the top level,
  everyone was inside it, so `impl Error for String` was accepted from any
  module and two of them could both write it. The fix is that **the top level
  is not a module**: a side of the rule counts only when there is a real module
  on it to be inside of. So `impl Error for T` must live in `T`'s module, and
  `impl Error for String` — where neither side belongs to anyone — is an orphan
  from everywhere and is rejected outright.

  This is not special-casing `Error`. It is the same correction for a prelude
  type, which belongs to no module either, and it leaves both real sides of the
  rule open: `std/traits` still writes `impl Cmp for Int32`, because it owns
  `Cmp`. The one place the top level still answers is a program that never
  writes a module header — a single compilation unit, with no other module an
  impl could have gone in, and nothing for the rule to say.

Two degenerate cases are rejected at compile time rather than given surprising
meanings:

- `def f : IOError` — not a union, nothing to propagate. `f()!` is an error.
- `def f : IOError | ParseError` — every member is an error, so `!` could never
  produce a value. Also an error. If a function genuinely never succeeds, its
  return type is `NoReturn`.

#### III.1.2 The propagation operator — **BUILT**

For `expr : T | E` where `E : Error`:

- if the value is a non-error member, `expr!` evaluates to it;
- if it is an error member, `expr!` returns it from the enclosing function.

The enclosing function's return type must already include `E`. There is no
implicit widening.

**Built, and it needed no type machinery.** `expr!` expands to

```
tmp = expr
return tmp if tmp.is_a?(::Error)
tmp
```

which is a purely syntactic rewrite. `Error` is an ordinary trait, so `is_a?`
narrows `tmp` in what follows to the union's non-error members — that *is* "if
the value is a non-error member, `expr!` evaluates to it". And the rule above,
that the enclosing function must already include `E`, is not enforced
separately: it is the ordinary return-type check on the `return` the expansion
wrote. `::Error` rather than `Error`, so a module with a type of that name
cannot change what the operator means.

The operator is attached-only: `f(x)!` propagates, `f !x` still means `f(!x)`.
`!` is left out of names by III.1.7, and the one place that still explains the
naming convention is a `def` name, where there is nothing to propagate.

III.1.1's two degenerate cases are rejected, along with a third the build found:
`!` on a type with **no** error member — `Int32?`, say, since `Nil` is not an
error. Without that check it compiles and silently does nothing, which is worse
than either case the section already named.

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

#### III.1.3 Handling — **BUILT**

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

Two conveniences for the cases where matching is overkill:

```
port = read_port().or(8080)     # value, or a default
port = read_port().or_panic     # value, or panic — the `unwrap` of this design
```

These are compiler-known on error unions rather than ordinary trait methods.
They have to be: by II.1 an ordinary method call on `Int32 | ConfigError` would
require *both* members to implement it, which is precisely the thing being
avoided here.

**Built, and like `!` they needed no type machinery.** Both expand to the same
`is_a?(::Error)` the operator uses:

```
tmp = read_port()               tmp = read_port()
if tmp.is_a?(::Error)           if tmp.is_a?(::Error)
  8080                            ::raise tmp.message
else                            else
  tmp                             tmp
end                             end
```

The result type falls out of that `if` rather than being computed. `.or` yields
the default unioned with the non-error members — `Int32` for the example above,
and honestly `Int32 | Char` if the default is a `Char`, since nothing here
narrows what the author wrote. `.or_panic` yields the non-error members alone,
because `raise` is `NoReturn`. And `tmp.message` is only reached where `tmp` has
been narrowed to the error members: they all implement `Error`, so by II.1 their
union does too, and the call resolves without this having to know which error it
holds.

The default is evaluated only when there is an error to recover from, matching
what a reader of `||` would expect.

Three things the build settled:

- **The two degenerate operands are rejected, as they are for `!`.** With no
  error member there is nothing to recover; with every member an error, `.or`
  can only ever return its default and `.or_panic` can only ever panic. Both
  are dead code wearing a fallback's clothes.
- **`or` and `or_panic` are reserved names in iyi.** That is what
  "compiler-known" costs: they are recognised at the call site by name, so an
  iyi program cannot define or call a method of either name. Only iyi — a
  Crystal file's `.or` is an ordinary call and is untouched.
- **`or_panic` currently raises.** Panics (III.1.4) are not built, so the
  `unwrap` of this design unwinds as a Crystal exception carrying the error's
  `message`. One line changes when panics land.

#### III.1.4 Panics, and cleanup — **`defer` BUILT; panics still PROPOSED**

Panics are for bugs, not control flow: index out of range, division by zero,
a violated invariant. They unwind and are catchable **only at task boundaries**,
so a panicking fiber cannot die silently. **Not built** — the task boundary is
part of III.1.4 that Part V.5 has to specify first, and until then `.or_panic`
raises (III.1.3).

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

**Built, and it needed no new machinery — only a new shape.** `defer x` expands
to wrapping the rest of its scope:

```
a                       a
defer x        ⟶        begin
b                         b
                        ensure
                          x
                        end
```

`ensure` already runs on a normal exit, on a `return` through it, and on an
unwind, which is the whole of what this section asks for: `!` expands to a
`return` (III.1.2), and a panic is a raise today. So nothing was added to the
runtime. What changed is where the cleanup is *written* — `begin`/`ensure` makes
you wrap everything after the acquisition, and `defer` names the cleanup at the
acquisition, which is the entire ergonomic point.

Two questions Part V.8 left open, both answered by Go's answers:

- **Ordering is LIFO**, and it is not a rule — a second `defer` expands inside
  the first one's body, so its `ensure` is the inner one and runs first. That
  is the only order that can be right when a later resource was built from an
  earlier one.
- **A `defer` may not propagate with `!`** (Appendix B #7), rejected in the
  parser with an error that says why.

One deliberate departure from Go:

- **The scope is the block, not the function.** A `defer` in a loop body runs at
  the end of each iteration rather than piling up until the function returns,
  which is Go's best-known wart with the feature — there, a loop that opens a
  file per iteration holds every one of them until the function is done. This is
  not an extra rule either; it is what the lowering does, and it is where Zig
  and Swift landed. The cost is that a `defer` cannot outlive the block it is
  written in, which is the same restriction stated from the other side.

`defer` is a reserved word in iyi and only in iyi: a Crystal file keeps it as an
ordinary identifier.

#### III.1.5 Nil is not an error — **SETTLED**

`T?` is `T | Nil`, and `Nil` does not implement `Error`. Absence and failure stay
distinct, as they are in Crystal today: `T?` for "not there", error unions for
"tried and failed". Existing flow typing (`if x = maybe_get`) handles nil, and
`!` does not touch it.

**No nil-propagating operator** (Appendix B #4). Not "not yet" — a second
propagating operator would give absence and failure the same shape, and the
pressure would then be to unify them, which ends with `Nil` implementing `Error`
and this section deleted. Flow typing is the better tool anyway: it forces the
branch to be written where the absence means something.

#### III.1.6 Error conversion — **SETTLED: none**

Rust's `?` silently converts error types through `From`. That is convenient and
it is also the mechanism by which Rust error handling became something people
write blog posts to explain: the set of errors a function returns stops being
what its signature says and becomes what trait resolution computes.

There is no implicit conversion here, and this is not a Draft 0 restriction
waiting to be relaxed (Appendix B #3). The error type must already be a member
of the caller's return union. Two things make that livable rather than
punishing:

- **Widening is not conversion.** Error sets are aliases (III.1.2), so a caller
  that admits more errors than it raises just names a wider alias. Union
  subtyping makes this free, and it covers most of what conversion is asked to
  do.
- **Real conversion is rare and should look it.** Deliberately hiding an
  `IOError` behind a `ConfigError` is a decision about a module's public
  surface. It is an ordinary function call, written where the decision is made.

### III.1.7 The conflict this design creates — **SETTLED — A**

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

**Decided: A.** It costs one Ruby convention and buys an operator with no
special cases.

The compiler enforces this today. `!` may not end a name in a `.iyi` file; `?`
still may. The mode comes from the file extension, so a `.cr` file is unaffected
and the prelude — which is full of `sort!` and `not_nil!` — keeps compiling.

The rejection applies at **call sites as well as definitions**. Banning only
`def sort!` would leave `arr.sort!` lexing as a single name, which is exactly the
room the operator needs. Since no iyi standard library exists yet, and no sample
used such a name, this cost nothing to adopt — which is why it was worth settling
before any stdlib code was written rather than after.

Two deliberate gaps:

- **Symbol literals are exempt.** `:sort!` is still legal in a `.iyi` file. A
  symbol is a literal, not an identifier, and since no iyi method can be *named*
  `sort!`, such a symbol can only ever refer to a Crystal method. The ambiguity
  being removed lives in call syntax, not in symbols.
- **Macro expansion is exempt.** Code expanded inside a `.iyi` file is parsed
  against a `VirtualFile`, so it lexes in Crystal mode and can still generate a
  name ending in `!`. The decision is about hand-written surface syntax, so this
  is defensible; closing it would mean making `VirtualFile` carry the mode of the
  file it expands into.

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

### III.3 `method_missing` — **CUT**

It requires an open method set, which R-3 closes by construction: a type's
methods are what its module declares plus its impls, all of it readable from
export metadata. A hook that answers calls nobody declared makes that set
unknowable, which is the one thing the compilation model needs it to be.

Grounded rather than asserted: in the Crystal standard library `method_missing`
appears **once**, as the hook definition in `object.cr`. **Kemal does not use it
at all.** Meanwhile `responds_to?` — the static alternative — appears across 34
files. The dynamic escape hatch is close to unused; the static one is what
people actually reach for.

**Cut.** `macro method_missing` is rejected in a `.iyi` file, with an error that
names R-3 and points at `responds_to?`. Only there — a Crystal file keeps the
hook, and the prelude's own definition of it is untouched. Compile-time
`responds_to?` works unchanged, which the error message is entitled to claim
because it is tested.

### III.4 Concurrency — **PROPOSED; III.4.4's gate cleared by the count in III.4.7**

This is the section where the design either beats Go or does not, so it is worth
being blunt about where Go actually loses. Not goroutines: they are cheap, the
scheduler is good, and nothing here improves on them. Go loses in three places,
all of them the same shape — **the compiler is not told anything, so the failure
shows up at runtime or not at all**:

1. **`go f()` is fire-and-forget.** Nobody waits, nobody is told, and a leaked
   goroutine is invisible. There is no construct that makes "this finished"
   checkable.
2. **Data races compile.** Sharing a map across goroutines is legal Go. `-race`
   is a runtime detector that finds what a particular execution happened to do.
3. **`context.Context` is a parameter, not a property of the work.** It is
   viral, appears in nearly every signature, carries values in a
   `map[any]any`, and cancellation is cooperative — you must remember to select
   on `Done()` in every loop.

The recommendation below turns each of the three into something the compiler
knows. It is not built, and none of it is free.

#### III.4.1 Concurrency is introduced by a scope, never by a call

There is no bare spawn. A task is started inside a group, and the group's block
cannot be left until every task started in it has finished:

```
pub def fetch_both(a : String, b : String) : Tuple(String, String) | IOError
  group do |g|
    x = g.spawn { read(a) }
    y = g.spawn { read(b) }
  end!
end
```

**This is `defer` again, and that is the argument for it.** III.1.4 built a
cleanup that runs on a normal exit, on a `!` propagation, and on an unwind, by
lowering to an `ensure`. A group is that same guarantee applied to a set of
tasks: the join is deferred to the end of the scope, so there is no exit — not a
`return`, not an error, not a panic — that leaves a task running. Go's leak is
unrepresentable, and it costs no new mechanism.

The cost is real and should be stated: a task cannot outlive the scope that
started it. Work that genuinely must outlive its caller is started from a group
that lives as long as it should — usually one owned by the program's entry
point — and that group is written down rather than implied. Trio, Kotlin and
Swift all landed here; Go is the outlier.

#### III.4.2 Cancellation belongs to the group, not to a parameter

Because a group owns its children, cancellation is a property of the scope, not
an argument threaded through every signature. There is no `Context` parameter.
A group cancels its remaining children when the block leaves early, when a
child fails under the group's policy, or when an enclosing group is cancelled.

**This has a runtime dependency, and it is the same class of dependency as
II.5's precise collector: it constrains the runtime from day one rather than
being added later.** Cancellation is worthless unless it reaches a task that is
*blocked*, so every blocking primitive — channel receive, IO, sleep — has to be
cancellable. A cooperative check the author has to remember is Go's answer, and
it is the part of Go's answer people get wrong.

#### III.4.3 A task's failure is an error member

The group returns what its tasks return, and an error from a task is an ordinary
member of that union — so `!` propagates it (III.1.2) and `case` handles it
exhaustively (III.1.3). Nothing new is required, which is the whole point:
Go needed `errgroup`, a library, because `error` carries no type information a
signature could have stated.

Default policy: the first failing task cancels its siblings and the error leaves
the group. That is `errgroup`'s behaviour, typed and built in.

#### III.4.4 Data races are a compile error — and R-3 is why that is affordable

A marker trait, `Share`, decided structurally: a type is shareable if every
field is shareable and none is mutable, or if it is a synchronised type that
owns its contents — `Mutex(T)` is shareable when `T` is. A value that is not
shareable cannot be captured by a spawned block or sent over a channel.

This is Rust's `Send`/`Sync` **without** ownership or borrowing, and it is worth
being exact about what that buys and what it does not. It rules out data races,
because anything two tasks can both reach is either immutable or synchronised.
It does not rule out deadlock, and it does not rule out logical races. Aliasing
is untouched — the restriction is on the *type*, not on who points at what,
which is exactly why it needs no borrow checker.

**The interaction that makes it affordable is R-3.** A structural marker is only
computable if a type's field set is final, and open classes are what would
break that: any module could reopen a type and add a mutable field, and
shareability would no longer be a property the defining module could state.
With R-3 it is, so `Share` is computed once by the module that declares the type
and travels in its export metadata (IV.2) like any other exported fact. A
consumer checks a spawn against a marker it read from a `.iyimod`, with no
global pass — the same result IV.4 reaches for coherence, for the same reason.

**This is the decision most likely to be wrong, so here is the alternative and
why it lost.** The other sound answer without ownership is Erlang's: no sharing
at all, tasks communicate only by copying. It is simpler and it is proven. It
was rejected because copying cost is not something a systems language can hide,
and because `Mutex(T)` gives the escape hatch that Erlang has to route through a
process. The count in III.4.7 was to be the arbiter, and it came back for
`Share`: the class this section feared turned out to be empty, and clean-sheet
iyi code is 77% shareable as written.

**It came back with an obligation attached, though, and the obligation is
now met.** Every failure in that clean-sheet code was a type holding an
`Array`, which made a **shareable immutable collection** something the standard
library owed the language rather than a convenience — without it the `Mutex(T)`
escape becomes the normal case, and an escape hatch used routinely is the
definition of a failed rule. `samples/iyi/std/list.iyi` is that collection, and
`samples/iyi/immutable.iyi` exercises it.

Two things building it settled that the count could not:

- **The collection cannot derive `Share`; it has to be trusted.** `List(T)`
  holds an `Array(T)`, so structurally it fails its own marker — and the
  counting tool duly reports it as failing, which is the demonstration rather
  than an embarrassment. What makes it safe is that it *owns* the array and
  never hands it out, and ownership is exactly what this design has no way to
  express, having refused a borrow checker. So `List` joins `Mutex` as a type
  the compiler trusts rather than checks. That list should stay short, but it
  cannot be empty. Rerunning the count with `List` present: 14 of 14 sample
  types pass once a shareable collection exists, against 10 of 14 without.
- **The constructor has to copy, for the same missing reason.** A caller that
  keeps the array it passed in could otherwise mutate the list from underneath
  a task holding it. Rust says "I own this now" and pays nothing; here it costs
  one copy at the boundary. `immutable.iyi` demonstrates the failure that copy
  prevents rather than asserting it.

#### III.4.5 What this settles about module-level state

II.9 recorded that the Kemal port replaced `Kemal::RouteHandler::INSTANCE` and
its neighbours with one application value, and noted that **nothing in the
design forced it** — separate compilation permits module-level state, so it was
taste and a suspicious comment in `router.cr:270` doing the work.

III.4.4 is the rule that was missing. Module-level mutable state is not
shareable, so it is not reachable from a task; it is either immutable or it is
behind a synchronised type. The Kemal port did by hand what this makes checked,
and Part V.5's question about the interaction between concurrency and
module-level mutable state is answered: there is no interaction, because the
combination does not compile.

#### III.4.6 What carries over from Crystal, and what does not

- **`Channel(T)` carries over**, with `T : Share`.
- **`select` carries over** unchanged.
- **`Fiber` does not carry over as a user-facing primitive.** It is how a task
  is implemented. Exposing a raw spawn puts III.4.1's leak straight back.
- **Parallelism is not free of the rest of the design.** IV.1d already measured
  that only the forking thread survives a `fork`, which is why the build daemon
  is single-threaded. A multi-threaded runtime and a fork-based daemon are in
  tension, and that is a measured fact rather than a prediction.

#### III.4.7 What `Share` costs — **COUNTED**

Every other rule in this document that costs users something was decided by
counting, and `Share` was not to be built before the same was done to it. The
count is `bench/share_count.cr`, which makes the marker mechanical: a field is
**mutable** if it is assigned anywhere other than the constructor, or if an
accessor macro generates a setter for it; a type fails if any field is mutable
or any field's type fails.

| | `samples/iyi` | the compiler's own source |
|---|---|---|
| types that can hold state | 13 | 483 |
| directly mutable | 0 — 0% | 118 — 24.4% |
| fail once field types propagate | 3 — 23.1% | 297 — 61.5% |
| …only because a collection is mutable | 3 — 23.1% | 2 — 0.4% |
| …only because of a generated setter | 0 | 42 — 8.7% |
| **pass `Share`** | **10 — 76.9%** | **186 — 38.5%** |
| pass given a shareable immutable collection | 13 — **100%** | 188 — 38.9% |
| hold class variables (III.4.5) | 0 | 3 — 0.6% |

**The class this section told itself to fear is empty.** "Immutable in practice
but holds a mutable field for one initialisation" describes no type here,
because a construction-only write is not a mutation — and letting it pass is
sound rather than lenient: a value is not reachable from another task until it
exists, so there is no second party to observe the write. Zero of the sample
types are directly mutable at all. The escape hatch that would have signalled a
failed rule is not needed for this reason.

**Nor for the reason next most likely.** Only 8.7% of the compiler's types fail
solely because of a generated setter, so "move the field into the constructor"
is not a fix anyone would be applying constantly either.

**What the count actually found is that the two corpora disagree, and why.**
Clean-sheet iyi code is 77% shareable as written and **100% shareable given one
missing piece**: every failure in it is a type holding an `Array`. The compiler
is 38.5% shareable and stays there, because its failures are not collections but
its own mutable object graph — `MainVisitor` with 35 mutated fields, `Compiler`
with 34, `Formatter` with 32, `Parser` with 30.

So `Share` is not a rule that fails; it is a rule that **prices a style**. It
costs nothing for code written the way the ported samples are written, and it is
close to unpayable as a retrofit onto a program built as a mutable workspace.

**The compiler is the control case, and it agrees with something already
measured the hard way.** IV.1d records that the build server could not be made
concurrent by adding fibers — the obvious fiber-per-connection version deadlocked
and died, and the daemon had to fork instead. That took two attempts and a
debugging session to discover. `Share` says the same thing about the same code
statically, before anything runs. A marker whose verdict matches a fact that
previously cost a failed implementation to learn is measuring something real,
not merely being restrictive.

**Verdict: keep `Share` (Appendix B #9), with one dependency.** The stdlib owes
the language a **shareable immutable collection**, and it is not optional —
without it a quarter of clean-sheet iyi types fail the marker for a reason that
has nothing to do with how they were written, and the only workaround is
`Mutex(Array(T))` everywhere, which is exactly the routinely-used escape hatch
that would mean the rule had failed. Rust answers this with an immutable borrow,
which is not available here; Erlang answers it with immutable collections by
default, which is. This is the same shape of dependency as II.5's precise
collector: a language rule that constrains the library from day one.

**Limits.** The tool reads syntax, not types: field types are matched on the
last segment of their path, so a name used in two namespaces is conflated, and
`Mutex(T)` is counted as mutable rather than as the synchronised escape it is
meant to be — which makes these numbers a lower bound on what passes. It also
cannot answer the second half of the original question, "how many of those are
reached from something that would plausibly be spawned", for the compiler, which
spawns nothing. For the samples it can: the three failures are `Nums`, `Words`
and the Kemal router's route table, and the router is precisely the thing a
server would share across tasks.

### III.5 Module initialisation — **PROPOSED; rules 1, 2 and 4 BUILT**

II.9 left this open with a concrete case: Kemal registers routes as a side
effect of top-level calls, which is legal, and the ordering guarantees across a
module DAG were never stated. Go's `init()` is the reference, and it is a
reference for what to avoid — importing a package runs code, order within a
package follows *file name*, an `init` that fails can only panic, and
`import _ "github.com/lib/pq"` exists as a language-level hack for a side effect
the compiler cannot see.

**III.4.5 already shrank the question.** Module-level mutable state is not
shareable, so it is either immutable or behind a synchronised type. What a
module initialiser mostly does, then, is compute constants — and the order in
which constants are computed is a much smaller question than the order in which
arbitrary side effects run.

**1. A module initialises after every module it imports.** R-1 makes `import` a
DAG, so this is a partial order with no cycles to resolve, and it needs no
analysis beyond the edges already in the artifact (IV.2).

R-1's DAG was a claim about the language and not about the compiler: a cycle
compiled. It was refused only where a module needed one of the other's names at
*declaration* time, because the second module of a pair is loaded from inside
the first's `import`, before the first's own body has been seen. Anything
resolving later got through — a cycle whose only crossing use sat inside a
`def` built and ran, and so did one that closed through the entry module, whose
initialiser is last by construction and so cannot precede a module that imports
it. A cycle is now an error naming the cycle, which is the same accident rule 1
stopped relying on above, and the one IV.4's coherence proof rests on.

**2. Between independent modules the order is *unobservable*, not merely
unspecified.** This is the rule worth having, and the compilation model already
pays for it: a module can only name what it imports (R-1), can only reach what
that module exports (R-2), and cannot reopen anything (R-3). So a module's
initialiser has nothing of an unrelated module to look at, and no program can
tell which of two independent modules went first. The tiebreak therefore does
not need specifying — there is no experiment that could detect it.

A rule nobody can observe is a rule that rots, so **debug builds shuffle the
order of independent modules. Built.** This is Go's own trick: map iteration was
randomised precisely to stop programs depending on an order the specification
never promised — and Go went further there than in its own `init`, which is
ordered by file name and therefore depends on one.

The compiler walks the DAG the way Kahn's algorithm does and picks at random
among the modules whose imports have all been placed, so no two debug builds of
a program need hand out the same order. Release builds keep the load order, so
what ships is reproducible; `IYI_INIT_SEED` pins a debug one, for a program
that fails under an order and has to be looked at twice.

**What it cost, measured.** Every sample was built under eight orders and all
eight produced identical output. The result is thinner than it sounds: of the
samples, only `modules.iyi` imports two modules that are independent of each
other, and their initialisers are declarations with nothing to observe. What it
does establish is that the reordering is safe — the tree the compiler hands the
rest of the pipeline is still one it types and generates code for — and that no
sample was quietly relying on load order. Evidence for what the rule *catches*
needs a program whose modules do work at initialisation, and there is not one
yet; III.4.5 is the reason to expect there never will be many, since
module-level mutable state is not shareable and an initialiser mostly computes
constants.

**Rule 1 was accidental, and now is not. Built.** `import` used to expand the
imported file *in place*, splicing its nodes where the directive stood, so a
module's top-level code ran at its import site and the order was textual. It
happened to agree with rule 1 — an `import` usually precedes the body that
needs it — but only usually. An `import` written below other top-level code
disagreed, and the disagreement printed:

```
module probe/main
puts "before"     # ran first, before `probe/a` had initialised at all
import probe/a
puts "after"
```

`import` now leaves a `Nop` where it is written and hands the loaded file to
`Program#iyi_module_inits`; `top_level_semantic` splices that list into the
tree, after the prelude and ahead of the program's own code. Loading is
depth-first and a module is appended only once the modules it imports already
are, so the list is in topological order and rule 1 holds by construction. The
entry file is not in the list, which is rule 1 applied to it: it imports
everything, so it initialises last. `samples/iyi/init_order.iyi` is the case
above, printing in the order the DAG fixes.

This is the separation rule 2's shuffle was waiting for — the order is now a
list the compiler owns rather than a property of where the text sits — and it
is the same separation Part IV needs, since an artifact cannot store an
initialiser it never separated. What is still missing for Part IV is the step
after: the list holds a module's *nodes*, not a callable initialiser in the
module's own object code.

**3. There is no `init()`. A module's top-level expressions are its
initialiser, in source order.** Go needs two mechanisms — dependency-ordered
package variables *and* `init` functions — and orders the second by file name,
which means adding a file can change behaviour. That failure has nowhere to live
here: `import a/b` resolves to `a/b.iyi`, one source file per module, so source
order is already total.

**4. Initialisation may not fail. Built.** If it can fail it is not
initialisation, it is work, and work belongs in a function the program calls
when it is ready to handle the failure. This is checkable rather than
aspirational, because errors are types: a top-level expression may not
propagate.

It turned out to be enforced already, but by accident — `!` expands to a
`return` (III.1.2), so it hit Crystal's rule about returning from the top level
and reported `can't return from top level`, which describes the expansion rather
than the rule. The propagating `return` is now marked, and the message names
III.5. Reported where the check already was rather than in the parser, because
the parser cannot see through a macro to know whether the expansion will land
inside a `def`.

**5. No import for side effects.** `import` brings a module's declarations; it
is not a way to run its registrations. The driver-registration pattern Go writes
as `import _` becomes an ordinary call the program makes, where a reader can see
it. This is the rule that costs the most: it is more code, and it removes a
convenience real programs use. The Kemal port is the evidence that the trade is
survivable — II.9 records that its singletons were replaced by one application
value and its routes returned as a table rather than registered into a global,
and that **nothing in the design forced it at the time**. This is the rule that
would have.

**The alternative that lost: lazy initialisation.** Module-level values could be
computed on first use, which removes ordering as a question entirely — Swift's
answer. It was rejected because it moves cycles from a compile-time
impossibility to a runtime failure, and because a guard on every access to a
module-level constant is a cost paid by every program to solve a problem that
R-1's DAG already prevents.

**Status.** Rule 3 is a description of what the compilation model already
forces and needed writing down more than building. Rules 1, 2 and 4 are built,
and so is the cycle refusal R-1 asserted and the compiler did not perform.
Rule 5 is the one with a real cost and no measurement behind it yet, and it is
the one to be suspicious of.

---

## Part IV — `.iyimod`, the module artifact

Everything in R-1 rests on this file. If it is wrong, separate compilation does
not work and the 95% prelude tax stays.

**The contract:** to compile module B which imports A, the compiler reads A's
`.iyimod` and never opens A's source. The prelude stops being 200k lines to
re-analyse and becomes a file to read.

### IV.1 Shape

One file per module, sections in a single container. Single-file because
replacement must be atomic — a half-written artifact that a later build treats
as valid is the worst failure mode a build cache has.

| Section | Contents |
|---|---|
| Header | magic, format version, compiler version, target triple, build flags |
| Hashes | interface / implementation / private (see IV.3) |
| Imports | DAG edges, each with the interface hash it was compiled against |
| Exports | types, signatures, traits, impls, constants |
| Macro bodies | serialised AST for exported macros and derives |
| Mono bodies | the bodies a consumer has to compile — source text, not IR yet |
| Initialiser | the module's own top-level code, as source text (IV.1g) |
| Object code | machine code for this module's own definitions |

Binary, for read speed. A `iyi mod dump` producing text is required, not
optional — an opaque cache format is one nobody can debug.

**The container is built, `Exports` carries the declarations, and a build can
be compiled against them.** `src/compiler/crystal/iyimod.cr` writes and reads
magic, format version, a section table and the `Header`, `Imports` and
`Exports` sections; `crystal build --emit-iyimod DIR` writes one per imported
module, `crystal mod dump FILE` prints it, and `crystal build --use-iyimod DIR`
compiles an `import` from the artifact instead of the module's source — see
IV.1f. `Exports` carries `pub def` signatures, exported type declarations with
their parameters, associated types and methods, and impl records with what they
answer, **and each type's own fields**. Layout templates, type descriptors and
constants are not in it — those are what codegen needs rather than what the
front end needs. **`MonoBodies` carries the bodies a consumer has to compile
itself, and `Initialiser` the module's own top-level code** (IV.1g). `Hashes`
and `MacroBodies` are declared in the `Section` enum and unwritten.

Fields were meant to be in that second list and are not, which is worth saying
plainly because the reason is a bug rather than a change of mind. A consumer
does not need a field to typecheck a call — and it does need one to
**allocate** the receiver. Without them `pub struct List(T)` read back as a
struct with no fields, and the consumer generated a `List(Int32)::new` that
allocated nothing while the module's own object code wrote to `@items`. That is
memory corruption, standing behind a link error that happened to fire first.
The line between "what the front end needs" and "what codegen needs" is not
the line between what travels and what does not.

**`ObjectCode` now carries a module's own machine code** — see IV.1g for what
that turned out to mean and for the two things it does not yet carry.

`std/list` reads back as:

```
imports
  std/enumerable
usings
  std/enumerable::{Enumerable}
exports
  struct List(T)
    def appended(item : T) : List(T)
    def at(index : Int32) : T
    def concatenated(other : List(T)) : List(T)
    def empty? : Bool
    def initialize(items : Array(T))
    def size : Int32
  impl Std::Enumerable::Enumerable for Std::List::List(T) forall T
    type Elem = T
    def each(& : (T -> Nil)) : Nil
```

**A signature is stored as the annotation the author wrote**, not as a
rendering of the inferred `Crystal::Type`. R-2 is what makes that sound —
everything exported carries full parameter and return types, so there is
nothing to infer — and it avoids inventing a second grammar for this file when
the consumer already has a parser for the first one. Where no annotation was
written it is recorded as absent rather than filled in: a constructor's result
is its type and nobody writes it down, and `def initialize(items : Array(T))`
above is that case rather than a missing one.

**Impl records had to be collected as they are declared**, not recovered
afterwards. An impl leaves no record of its own — it works by making the target
type include the trait, and once analysis is over that is indistinguishable
from any other ancestor. R-3 is what makes the collected set complete: an impl
may only live in the trait's module or the type's, so `std/traits` carries
`impl Cmp for Int32` and no third module could have carried it instead.

Because the section is still partial, **`mod dump` says so on every dump**. A
reader cannot tell an absent field list from an empty one, and taking a partial
surface for a complete one is the mistake this file cannot afford.

Two properties were built in from the start rather than retrofitted, because
neither can be added later without a format break. **Replacement is atomic**: a
sibling temporary is renamed over the target, so a reader sees the old file or
the new one and never a half-written one — the worst failure a cache has is the
one that looks fine. **Unknown sections are skipped**, which is what the table
is for: a consumer wanting `Exports` must not have to page in `ObjectCode` to
reach it, and forward compatibility falls out of the same property. Both are
covered in `spec/compiler/iyimod_spec.cr` rather than asserted here.

**Target:** reading the prelude's `.iyimod` should cost single-digit
milliseconds, against the **~1.0 s** its top-level analysis costs today —
measured, not estimated, and 2× the 0.5 s this section claimed before anyone
had run the experiment. See IV.1a for what that does and does not buy.

### IV.1f Reading the artifact instead of the source

`crystal build --use-iyimod DIR` resolves `import a/b` to `DIR/a/b.iyimod`
where it would have opened `a/b.iyi`, and **does not open the source**. Not
"prefers the artifact": the file need not exist. Seven of the eight samples
compile with the imported module's source deleted, `immutable.iyi` among them —
a generic type, a 575-line trait with an associated type, and a generic impl
that answers it.

**The artifact is rendered back to declarations and those are parsed.**
`crystal mod dump --declarations` prints exactly the text the compiler reads,
which for `std/list` is its `module`, its `import`, its `using`, `pub struct
List(T)` with six headers and no bodies, and the impl with its `type Elem = T`.
Text rather than a serialised AST because the signatures already are text: the
parser that read the module is the one that should read its declarations back,
and a second grammar for this file would be a second thing to keep correct. A
diagnostic that points into a `.iyimod` names a line of that output, which is
why it is printable.

**A call to a def from an artifact is typed from its return annotation.** There
is no body to visit and there is not meant to be one — R-2 guarantees the
annotation is written, and IV.2 keeps the body out. That is the whole of what
the front end gets, and it is also the boundary: a module read this way
contributes an **initialiser only because one now travels** in a section of its
own (IV.1g) — its top-level code is not a declaration, so `Exports` was never
going to hold it. What is still left behind is code inside a *type* body, and a
build that would generate code against a module with one is refused rather than
given a program that runs with the setup missing. IV.1a said the same thing
from the other direction —
codegen needs the prelude's tree for reasons caching analysis does not remove.

**Three things had to travel that the format did not carry**, each found by a
real module rather than by reading:

1. **The rest of the `def` line.** The block annotation, `forall`, `abstract`,
   the receiver, and a parameter kept whole so its default value survives.
   `Enumerable`'s `map(& : Elem -> U) : Array(U) forall U` needs three of the
   five in one signature.
2. **An impl's own methods.** They are the impl's, not the target's:
   `impl Cmp for Int32` puts `cmp` on a prelude type this module does not
   export, so recording it against the target loses it. This is also why
   `each` appears under the impl in the dump above and not under `List`.
3. **The module's `using` directives.** A signature is stored as the annotation
   the author wrote, and an annotation is written in a context: `pub def
   handle(ctx : Context)` resolves `Context` through a `using` further up the
   file. `std/list` never noticed, because its signatures name only its own
   types; the Kemal port's first exported signature does not. Carrying the
   annotation without what resolves it was carrying half of it.

**Measured**, best of 7 runs, `immutable.iyi`, top-level pass only:

| | top level |
|---|---|
| prelude alone (empty program) | 0.886 s |
| + `std` from source (722 lines) | 0.901 s |
| + `std` from its `.iyimod` | 0.884 s |

The 722 lines cost 15.5 ms from source and nothing measurable from their
artifacts, so on the modules it is applied to the mechanism delivers what it
promises. It is also invisible, because 0.886 s of prelude is next to it. That
is the 95% prelude tax stated as a measurement rather than as an argument, and
it is why item 3 of the 0.1.0 list — a prelude small enough to be one of these
modules — is what decides the schedule and not this section.

### IV.1g `ObjectCode` — the module's own machine code

**The unit is the object file, because codegen already splits that way.** Every
method is emitted into the LLVM module of the type that owns it, one object
file per type, and the split is a **partition**: on the Kemal port, 23 units
and no symbol defined by two of them. So "this module's own definitions" is a
set of whole object files rather than a filter inside one, and carrying them is
copying bytes rather than teaching codegen a second way to lay out a program.

A module's units are the module type itself — where its own `pub def`s are
owned — plus every non-generic type declared under it, recursively.
`kemal/router` owns five (`Router`, its three nested records, `Context`) and
`kemal/dsl` one. `app/greeter`'s artifact comes out at 3,177 bytes, of which
2,736 are an ELF object defining `polite`.

**A generic type's instantiations are deliberately not among them**, and
carrying them was tried first because it looks obviously right. `--emit-iyimod`
runs inside an ordinary build, so the producer's instantiations *are* the
consumer's, and `List(Int32)`'s unit appeared to belong in `std/list`'s
artifact. It does not: `List(Int32)::new` is **synthesized** from `initialize`
rather than read from the artifact, so the consumer generates its own copy and
the link fails on a duplicate symbol. The deeper reason is that the appearance
depends on the two builds being one build, which is the arrangement this file
exists to end — which instantiations exist is decided by whoever writes
`List(Int32)`. They are `MonoBodies`' business (IV.2).

**Two properties had to hold for this to be possible at all, and both were
checked rather than assumed.**

*Symbol names carry nothing build-specific.* A method's symbol is its owner
type, its name, its argument types and its return type, escaped — no counter,
no path, no hash of the build. Two builds that agree on the types agree on the
name, which is what lets one build's object file be linked by another's.

*A type id is already an external reference.* Type ids are integers assigned by
a global pass, so a module compiled alone cannot know its own — the obvious
reading is that separate compilation is therefore impossible without a format
that carries them. It is wrong: the router's unit lists `Kemal::Router::Router:
type_id` among its **undefined** symbols. The number is resolved by the linker
from a definition in `_main`, not baked into the code. Whoever assigns the ids
defines the symbols, and everything else relocates against them.

**And a program built from an artifact runs.** `--use-iyimod` no longer implies
`--no-codegen`. A def read from a `.iyimod` is *declared* rather than defined —
the same shape a `lib` function takes, and for the same reason: the body is
somebody else's — the artifact's object files are unpacked into the build's
own output directory, and the linker joins the two.

```
crystal build --emit-iyimod mods -o from-source main.iyi   # 42
rm app/twice.iyi
crystal build --use-iyimod  mods -o from-artifact main.iyi # 42
```

That is the first thing in this document that produces a program rather than a
typecheck, and `spec/compiler/iyimod_spec.cr` runs both binaries and compares
what they print.

**Two bugs it found, both of the kind that would have linked and lied.**

*A def read from an artifact must not be inlined.* Its body is absent, which
reads to codegen as the simplest possible body — `Nop` is the first case
`try_inline_call` matches — so a call to the module's code was being replaced
by nothing at all. It did not link, because an absent body also has no type;
had it, the program would have run and computed the wrong answer.

*`type?` is not `@type`.* `ASTNode#type?` answers `@type || freeze_type`, so a
def whose return annotation has been resolved reads as typed while `@type` is
still nil — and `Def#mangled_name` reads `@type`. Setting the type only `unless
type?` therefore left the front end correct and handed codegen a symbol with no
return type on the end, which is not the symbol the artifact defines. The
linker caught it. Nothing else would have.

**Three more things had to travel, each found by the linker on `modules.iyi`** —
build it, delete `app/greeter.iyi` and `app/formal.iyi`, build again from the
artifacts. Four undefined symbols, then two, then none.

*A method inlined away has no symbol to carry.* `title` returns a string
literal, so every call site inlined it and the producing build emitted no
function — but the consumer has no body to inline and calls it by name. Two of
the four. A build writing an artifact therefore stops inlining the methods that
artifact describes: code somebody else will call by name has to be defined. The
check asks the *instance* type, because a module-level `def` is owned by the
module's metaclass, which is most of what a module exports.

*A module carries private copies of what it calls.* `String::interpolation
<String, String, String>` is in the prelude's `String` unit, and the consumer's
own `String` unit holds whatever *the consumer* instantiated, which need not
include it. Carrying the producer's whole `String` unit is not an option — it
would define symbols the consumer also defines, and the linker refuses that —
and sub-unit granularity cannot be had by copying bytes. So the callee is
copied into the module's own unit with **internal linkage**, transitively.

The alternative was `linkonce_odr` on Crystal's functions, so duplicates merge
at link — what C++ and Rust do with template instantiations, and sound here
because the header already asserts the same compiler, triple and flags. It was
rejected for reach: it changes codegen for **every** build in this fork to fix
a problem that belongs to artifacts. The price of the private copy is
duplication — each module carries its own `String::interpolation` — and one
consequence worth knowing, that a proc taken to such a function has a different
address on each side of the boundary. A C function is never copied: it is a
declaration with no body whoever asks, and internal linkage on a declaration is
invalid IR, which `write` and `exit` reach from the prelude's own `puts`.

*And a program that links an artifact defines every type id.* The copy above
brought its own undefined symbol — `String:type_id`, which the same program
built from source resolves without trouble. Type-id globals are emitted on
demand, so they exist only where *this* program wanted one, and a build cannot
see from an object file which ones that object needs. It therefore defines them
all. An `i32` per type is not a cost worth a cleverer answer, and the artifact
must keep carrying a reference rather than a value: two programs number their
types differently.

**Some bodies have to travel, and `MonoBodies` is which ones.** A module's
machine code answers for a method the producer could compile. Two kinds it
cannot, and they are the two exceptions IV.2 already names:

- **A generic type's methods.** `List(Int32)#size` exists once per
  instantiation and the instantiations belong to whoever writes them. A
  consumer that writes `List(Float64)` needs a method the producer never made.
- **A trait's default methods.** `to_a` is stencilled onto the implementing
  type, and the implementing type may be the *consumer's*. There is no name
  `Samples::Collections::Nums@Std::Enumerable::Enumerable#to_a` could have been
  compiled under in the producing build, because `Nums` did not exist in it.

Both ship their bodies as **source text**, rendered back into the declarations
a consumer parses. IV.1's table asks for serialised typed IR, which is faster
and is a second grammar to keep correct; text is the choice `Exports` already
made, for the reason IV.1f gives, and IR can replace it without changing what
travels.

**An impl is the third case, and it is the one that fixes the rule.** An impl
defines methods *on its target*, so they are emitted into the target's unit —
and the artifact carries a unit only for a non-generic type the module
declares. `impl Cmp for Int32` in `std/traits` therefore puts `cmp` in the
*prelude's* `Int32` unit, which no artifact can carry without defining every
other `Int32` method the consumer also defines. So an impl's bodies travel
**unless** its target is a non-generic type this module declares — and the
"unless" is not caution. Shipping them always makes the consumer compile a
method the artifact's object code already defines, which is a duplicate symbol.

**Two duplicates found by that boundary, both about a method nobody wrote.**
`Greeter::new` is synthesized from `initialize` rather than read from an
artifact, so nothing marked it as coming from one: the producer emitted it into
`Greeter`'s unit and the consumer synthesized its own. The types an artifact
declares are now marked, and codegen declares their methods rather than
defining any — the artifact is authoritative for a type whose object code it
carries. The mark is on the declared type and not on its instantiations, which
is the distinction that makes it work: `List(T)` is the artifact's, and
`List(Int32)` is compiled here like any other type.

**And the artifact's declarations join the tree.** They were being parsed,
accepted and thrown away, which is enough for name lookup and no more: an
instance variable's type is settled by `TypeDeclarationVisitor`, a separate
pass over the tree. So `@items : Array(T)` read from an artifact was a
declaration the compiler had parsed, accepted, and could not see — "can't infer
the type of instance variable `@items`" on the line that assigns it. A file of
declarations still contributes no initialiser, because there is nothing in it
to run; that is a property of the content, not of how it is plumbed.

**And the module's initialiser travels too.** It is the one part of a module
that is neither a declaration nor the body of one, and III.5 is entirely about
it: it has to *run*, in DAG order, before anything that imports the module.
Nothing else can produce it — a consumer that never opens the source cannot
invent the module's constants, its proc literals, or the statements between
them. So it goes in a section of its own, as source text, rendered back inside
the module's own namespace; the consumer parses it and it takes its place in
the import order like any module read from source, because that order is over
modules and not over text. `init_order.iyi` — whose whole subject is that
ordering, and one of whose `import`s sits below a statement of its own — prints
the same five lines in the same order from its artifacts as from source.

The section is not in IV.1's table. The table had a row for declarations and a
row for bodies of declarations and no row for this, which is the gap rather
than an addition: a module is not only what it declares.

**What still does not travel is code inside a *type* body** — a class
variable's initialiser, which belongs to the type rather than to the module's
top level. `has_initialiser` now means exactly that, and a build that would
generate code against such a module is refused, naming the module and why. The
distinction is worth the precision: the flag used to mean "has anything to run"
and refused three modules that were fine.

**Where that leaves the eight samples.** Five import a module at all; the other
three (`hello`, `generics`, `errors`) are single files and exercise nothing
here.

| sample | from its artifacts, source deleted |
|---|---|
| `modules` | **builds, links, runs, identical output** |
| `immutable` | **the same** — a generic type, a 575-line trait, a generic impl |
| `collections` | **the same** — the consumer's own type implementing the trait |
| `init_order` | **the same** — including III.5's ordering, line for line |
| `webapp` | refused at `--emit-iyimod` — R-2, `namespace` takes an unannotated block |

**Four of the five, and the fifth is not this section's failure.** R-2 refuses
`namespace` because it is exported and takes a block it does not annotate,
which is IV.2's rule working: the body stays behind, so there is no `yield`
left to infer the block from. It has been true since before `ObjectCode`
existed, and IV.2 already counts it as the one method the rule costs.

And one thing none of the five reaches, which the Kemal port would:
**prelude generics instantiated at this module's own types.** The router's body
builds an `Array(Kemal::Router::Router::RouteDefinition)`, and that unit is
named after `Array` — not after anything `kemal/router` declares — so the
ownership rule does not catch it. **Twelve of the router's 41 undefined symbols
are of this kind.** They belong to this module by the same logic R-3 uses for
impls: the instantiation exists because of this module and no other.

Underneath all of it stays the fact that **an artifact carries what the
consuming build reached**, rather than the module's surface. Codegen is
demand-driven and `--emit-iyimod` lives inside an ordinary build. A module
compiled on its own would instantiate every exported def at the signature R-2
makes it write down — and compiling a module on its own is the command that
cannot precede the artifact it produces.

**Deciding "does this module have an initialiser" was wrong three times**, and
each was the kind of mistake a spec cannot find by reasoning — the same class
IV.6 records. The test walks a module's top level and calls anything it does not
recognise as a declaration an initialiser, which is the safe direction: a
refusal explains itself and a missing setup does not. What it did not recognise:
the file is already wrapped in a `ModuleDef`, because `apply_module_header`
turns `module a/b` into one, so **every** module answered "no initialiser" and
the flag was written and always false. Then `pub struct List(T)` is a
`VisibilityModifier` around the declaration, not a declaration, which refused
three samples that were fine. Then `type Elem = T` is an `AssocTypeDecl`, which
refused the two that have associated types. Each looked like the last bug and
was a different one.

**A reader that does not want it does not pay for it.** `ObjectCode` is the
largest section in the file and is written last; `IyiMod.read` seeks past it
unless asked, so `import` — the front-end reader this whole file exists to make
fast — never allocates it. A `--no-codegen` build omits the section entirely
rather than writing it empty, and can still typecheck against a module whose
initialiser rules out generating code.

### IV.1a What the artifact actually buys — measured

The prelude fork probe (`IYI_FORK_PROBE=1`, temporary instrumentation) analyses
the prelude, forks, and compiles the user program in the child. Restoring the
prelude then costs a `fork`, which is the ceiling no serialised artifact can
beat. Front end only; 5 runs, median; single-threaded compiler build.

| Program | Front end today | Artifact (top level cached) | + prelude-aware passes |
|---|---|---|---|
| `hello.iyi` | 1.58 s | 0.47 s — 3.4× | 0.049 s — 32×† |
| `webapp.iyi` (the Kemal port) | 1.54 s | 0.45 s — 3.4× | — |
| 19.5k lines, 1500 types, 4500 methods | 2.39 s | 1.39 s — 1.7× | 0.94 s — 2.6×† |
| prelude-free floor (`--prelude=empty`) | 0.09 s | — | — |

† Read IV.1e before quoting these. The third column measures a prelude analysed
all the way through `main`, which is more than Part IV's artifact carries and
which fails on any program that subclasses a prelude type. The number is a
ceiling on a configuration that does not work, not a target.

**The third column is reachable, and it was verified past the front end.** The
probe can go on to emit object code (`IYI_FORK_CODEGEN=1`). Under both models the
emitted object has a **byte-identical symbol table** to a normal build's — 3741
symbols, same size, differing only in 0.1% of bytes. So a front end that never
looks at the prelude produces the same program.

Getting there took one wrong turn worth recording, because it is the kind of
mistake this design invites. The first attempt handed codegen only the *user*
tree and failed with:

```
Missing __crystal_raise_overflow function
```

The tempting reading is that `main` is demand-driven and a prelude analysed
alone never instantiates what only user code reaches. That reading is wrong.
`__crystal_raise_overflow` is a `fun` in `src/raise.cr`, and **codegen emits
`fun`s and top-level code by walking the AST** — so the prelude's tree has to
reach codegen whatever the front end did with it. Once it does, the object is
equivalent.

Which is exactly what IV.1's object-code section is for: the prelude's machine
code comes from the artifact, not from re-analysing its source. The front end and
codegen need the prelude for *different reasons*, and only the front end's reason
is removed by caching analysis. Anyone building this will hit the same error and
should not conclude from it that the design is unsound.

### IV.1b End to end, with a real binary at the end

The probe can also link, so the claim can be checked the only way that really
counts: build `hello.iyi` inside the fork and run what comes out. Both models
produce a binary whose output is identical to a normal build's.

| | front end | whole build | vs Crystal today |
|---|---|---|---|
| today | 1.48 s | 2.19 s | 1.00× |
| artifact model | 0.47 s | 1.13 s | **1.9×** |
| + prelude-aware passes | 0.049 s | 0.74 s | **3.0×** |

Reaching this needed a runtime fix, worth recording because it is not
iyi-specific. **A forked child could not spawn a subprocess at all.**
`Signal.after_fork` recreates the signal pipe but never restarts the
`signal-loop` fiber that reads it — only the forking thread survives a fork — so
a `SIGCHLD` was written into a pipe nobody read and `Process#wait` blocked
forever. That silently broke the linker, `expand_lib_flags`, and `macro_run`
alike; restarting the reader fixes all three.

So a prelude daemon — analyse once, fork per build — is not blocked on `.iyimod`
at all.

### IV.1c Two bugs the split found, which `.iyimod` would have hit anyway

Making the artifact model compile the compiler itself took fixing two defects in
`TypeDeclarationProcessor`. Both are latent today and unreachable in a single
run, and both are certain to reappear the moment analysis is restored from an
artifact rather than recomputed. They are the first concrete evidence of what
Part IV costs beyond the file format.

1. **A module's guessed instance variables never reached types that included it
   later.** `process_owner_guessed_instance_var_declaration` returns early when
   the owner already has the variable — which doubles as "already processed" —
   and that skipped the transfer to `raw_including_types`. When `IO::Buffered` is
   analysed in one run and `Socket` includes it in the next, `Socket` never gets
   `@in_buffer`, and it surfaces far away, as a nil assertion while attaching the
   initializer.

2. **Redeclaring a variable discarded its initializer.**
   `declare_meta_type_var` always builds a fresh `MetaTypeVar` and replaces the
   old one. In a single run that is safe, because declarations are processed
   before initializers are visited. Across a split it silently dropped every
   prelude class variable's initializer — caught here by the non-nilable check,
   but the same clobbering would have left them uninitialized at runtime.

3. **A per-pass flag stayed set across passes.** `top_level_semantic_complete`
   guards `TypeNode#instance_vars` and `#has_inner_pointers?` in macros, which
   must refuse to answer before instance variables are declared. A second
   top-level pass inherited the flag from the first, so the guard did not fire
   and the macro got an *empty* list instead of an error — then generated code
   against variables the type did not have yet. It is now cleared at the start
   of every top-level pass, which is a no-op in a single run.

The pattern in all three: **passes assume they see the whole program once.** Not
"they are slow", which is what IV.1a measured — they encode single-run
assumptions in ways that only fail when a program is analysed in two pieces.
That is the real content of "make the passes prelude-aware", and it is found by
running the split, not by reading the code.

### IV.1e What the fourth failure revealed about the experiment

The full model's remaining failure on the compiler was worth chasing to the
bottom, because the answer is about the experiment rather than about a bug.

Two plausible causes were wrong. It was not `finished_hooks` accumulating across
runs, and it was not the flag above. The actual chain, from the compiler's own
stack rather than from reading:

```
force_add_subclass → add_subclass → notify_subclass_added → Call#on_new_subclass
```

**A subclass observer is a `Call` registered during `main`, and notifying it
re-types that call.** In an ordinary compile this can never fire mid-declaration:
every type exists before `main` runs. Under the full model the parent had already
run `main`, so the child's top-level pass declaring `TypeException < CodeError`
re-typed a prelude call against a type whose instance variables were not declared
yet — hence a complaint about `@inner`, three layers away from the cause.

Holding those notifications until the end of the top-level pass fixes that layer
and exposes the next one: `instance variable '@dependencies' of Crystal::ASTNode
must be Crystal::SmallNodeList, not Nil`, i.e. nodes bound by the completed run
being re-bound by the new one.

That deferral is **not** in the tree. It passed the whole suite — 3350 semantic,
1811 codegen, 3962 parser — so removing it was a scope decision rather than a
correctness one: it changes a core mechanism to serve a configuration that still
does not work, and the knowledge it produced is this section. Whoever builds the
real prelude-aware passes will need it, and will find it here.

**The pattern is the finding.** The full model restores a prelude analysed
*through `main` and `cleanup`* and then declares new types against it. Part IV's
artifact deliberately carries types, signatures, impl records and layout
templates — **not typed method bodies**. So the full model was measuring a
configuration the design does not ask for, and its layered failures are what
"analysis complete, now declare more types into it" costs.

This corrects the third column of IV.1a: **32× is the value of a configuration
that does not work**, not a target. The genuine version of "prelude-aware passes"
— parent stops at the end of the top-level phase exactly as the artifact model
does, and the child's *later* passes skip prelude subtrees — has not been built
or measured. It is the honest next experiment, and it is unaffected by everything
above, because it never runs `main` twice.

**Where it stands:** the artifact model now compiles all nine gate programs, a
targeted regression for each bug above, and the compiler itself. The full model
still fails on the compiler, for the fourth reason above, so its 3.0× remains a
result on small programs. The artifact model's 1.9× is the one that survives
contact with a real codebase.

The other honest limit: codegen's own prelude cost is untouched — 0.7 s of the
2.2 s build, now the dominant term — and reducing it is the object-code
section's job, which Crystal's existing `.o` reuse already does part of.

### IV.1d The daemon — the measurement, shipped

`crystal daemon` analyses the prelude once and forks a child per build, so the
1.9× above is available to an actual user without `.iyimod` existing. Measured
on `hello.iyi`, five consecutive builds with the output deleted each time:

| | |
|---|---|
| `crystal build` | 2.19 s |
| `crystal daemon build` | **1.12–1.31 s** |
| prelude analysed once, at startup | 1.07 s |

Diagnostics and exit status are identical to a normal build on all nine gate
programs, and the binaries it produces behave identically on all four samples.

Three things it has to get right, all of which are about being a *daemon* rather
than about compilation:

- **Staleness.** It holds an analysed prelude across edits to that prelude. The
  fingerprint is every file in `program.requires` with its modification time,
  checked per request; a changed prelude is re-analysed before the build. Tested
  by adding a method to `String`, watching a previously failing program compile,
  removing it, and watching the error come back.
- **Flags.** Macros branch on flags, so an analysis made under one set cannot
  serve a build under another. The daemon keeps one prelude *per flag set*,
  keyed on everything that changes what the prelude analyses to, and warms a new
  one from builds that already succeeded — the first `--release` build is cold,
  the rest are not. Measured: 0.46 s on a cached flag set, 1.48 s cold, and
  0.52 s once warmed.

  It warms only from arguments a build has already parsed successfully, and that
  is the whole safety argument: turning arguments into a compiler means running
  the option parser, and the option parser exits the process on bad input. Doing
  that on arguments a client made up would take the daemon down on a typo. It
  also warms only while nothing is in flight, since analysing costs about a
  second and this loop is what relays every build's output.

  Bounded by `CRYSTAL_DAEMON_PRELUDES`, default 3, because each analysed prelude
  is roughly 180 MB of live heap. Past the bound, extra flag sets stay cold
  rather than being evicted — a cold build is slow, and evicting the set someone
  is actively using would make every build slow in turn.
- **Its own socket.** `UNIXServer#close` unlinks the socket file, so the forked
  child closing its inherited copy took the daemon's address away from every
  later client while the daemon went on listening, looking healthy. `close(delete:
  false)` in the child.
- **Its own compiler.** A daemon holds an analysed prelude *and the compiler that
  analysed it*. Rebuild the compiler and it keeps serving builds from the old
  one, with output that looks entirely normal — the worst shape a stale cache
  can take. It now records its executable's size and modification time before
  opening the socket, checks per request, and refuses with an instruction to
  restart. Nanoseconds, not seconds: a rebuild landing in the same second as the
  daemon's start is exactly the case to catch.

**Using it should not require remembering it.** With `CRYSTAL_DAEMON_SOCKET` set,
an ordinary `crystal build` is served by that daemon — 1.00 s against 1.85 s on
the same warm cache — and falls back to a normal build, with a line saying so,
when nothing answers. Opting in to a daemon must never be able to *stop* a build;
the worst it may cost is the speedup.

**Builds run concurrently, and getting there took two attempts.** The obvious
fiber-per-connection version deadlocks and then dies: a forked child inherits the
parent's live fibers, and the scheduler runs them as soon as the child blocks on
IO, so another build's relay fiber writes to descriptors this child has closed.
**Fork-based build servers cannot be made concurrent by adding fibers** — that is
the transferable part.

What works is one fiber and one `poll(2)` over the listener plus every in-flight
build's two pipes. Crystal has no `IO.select`, so the binding is declared in the
daemon (at file scope: reopening `lib LibC` inside a class defines a *nested* lib
of the same name instead of extending the real one). A child also closes every
*other* in-flight build's connection and pipes, or an inherited copy outlives the
build that owns it.

Measured: four concurrent builds finish in 2.0 s against 1.16 s for one, and
eight — half of them deliberately failing — in 3.2 s with every exit status and
every diagnostic delivered to the client that asked for it.

Two limits worth naming: the request is read inline, so a client that connects
and then stalls holds up the loop; and writes to a client are blocking, so a
client that stops reading stalls the relaying of other builds. Both are fine for
a local build daemon and neither is fine for anything exposed.

**Packaging.** The server is a separate binary, `make crystal-daemon`, built with
`-Dwithout_mt`. This is not a workaround to be removed later: only the forking
thread survives a `fork`, so a multi-threaded runtime hands the child a broken
one, and Crystal refuses `fork` in such a build at compile time — correctly. The
client does not fork, so it stays in the normal compiler; `crystal daemon start`
execs the server binary (or `CRYSTAL_DAEMON`, if set) and says how to build it
when it is missing.

The cost of that split is that the daemon's builds code-generate sequentially.
Measured, it does not eat the win: on a 19.5k-line, 1500-type program the normal
multi-threaded build takes 3.40–4.25 s and the daemon 2.59–2.77 s, with identical
output. That is one program on one machine, not a general claim — a program whose
codegen both dominates and parallelises well could come out differently.

Against the same multi-threaded compiler as baseline: `hello.iyi` 2.21–2.26 s
normally, 1.16–1.24 s through the daemon.

**What it is not.** It cannot cross machines or sessions, it holds one prelude
and so serves one flag set quickly, and it builds one program at a time. It is
scaffolding that `.iyimod` will replace — worth having because it delivers the
win now and because every latent single-run assumption it trips over is one
`.iyimod` would have tripped over later.

It is covered by `spec/compiler-cli/crystal-daemon_spec.cr`, which starts a real
daemon on a private socket and checks the properties that would make it subtly
wrong rather than visibly broken: a served build's exit status and diagnostics
match a normal build's byte for byte, `stdout` and `stderr` stay separate, a
second build is still served after the first, and a build whose flags differ from
the daemon's prelude is still correct. `make cli_spec` builds the server binary
so the suite actually exercises it; if it is absent the examples report as
pending with the reason, rather than passing silently.

**The artifact alone is worth 3.4×, not 20×, and the gap is not the artifact's
fault.** Where the child's 0.45 s goes:

| Pass | Cost with prelude pre-analysed |
|---|---|
| top level | 0.004 s (was 0.99 s) |
| class-var initializers | **0.285 s** |
| main | **0.162 s** |
| everything else | ~0.04 s |

The top-level pass — the only one `.iyimod` removes — drops by 250×. What
remains is that **six of the eleven semantic passes re-walk the prelude AST and
three re-walk the whole type graph**, whatever put the prelude there. Class-var
initializers and `main` are 90% of the residual.

**So Part IV is necessary and not sufficient.** A serialised prelude that the
later passes still traverse converts a 1.5 s front end into a 0.45 s one; the
floor needs those passes to skip prelude nodes too, which the experiment above
shows is achievable and worth another 10×. That is a separate piece of work from
the file format, it is larger than the format, and it should be planned as such
rather than discovered afterwards.

Two secondary results from the same instrument:

- **Half the top-level cost is parsing.** 304 files, 107,719 lines: 0.57 s to
  parse, 0.54 s to visit. A cache removes both; a faster parser removes one.
- **User code stays nearly free until the program is large.** `webapp.iyi` costs
  the same as `puts "hi"`. At 19.5k lines user code finally dominates and the
  win falls to 1.7× — the prelude cache matters most to the small, frequent
  builds, which is where build-speed complaints come from.

### IV.2 What goes in Exports — and what is deliberately kept out

**In:**

- **Type declarations.** Name, kind, generic parameters, field names and types.
  **Built.** A field travels as its resolved type rather than as the annotation
  the author wrote, which is a departure from how signatures travel and is
  deliberate: a field is not part of the surface a consumer writes against, it
  is what the consumer has to allocate. For a generic type the resolution is in
  terms of its own parameters — `List(T)`'s `@items` is `Array(T)` — which is
  what lets one declaration stencil at every instantiation.
- **Layout templates.** Size, alignment, and pointer map — expressed as a
  *function of the type parameters' shapes*, not a fixed layout. `Array(T)` is
  three words regardless of `T`; `Tuple(Int32, String)` is not. R-4 needs the
  template to stencil at any shape.
- **Type descriptors.** A runtime type id per exported type. II.6 established
  that dictionaries carry type identity, not just pointer maps, because
  `select(type : U.class)` filters by runtime type.
- **Signatures** of `pub` functions and methods. Parameters, return type, the
  `where` bounds from II.6, and everything else on the `def` line: the block
  annotation, `forall`, `abstract`, the receiver.
- **Trait declarations.** Required methods, associated types, and the
  *signatures* of default methods.
- **Impl records.** Every `(Trait, Type)` pair this module provides, with what
  the impl answers — its `forall` parameters, its trait arguments, its
  associated types, and the methods it defines. This is what lets a consumer
  answer "does `Customer` implement `ToJSON`?" without reading `Customer`,
  which II.4 depends on.
- **The module's `using` directives.** Not part of its surface: nothing here is
  reachable through them. Part of what its surface *means* — a signature is
  stored as the annotation the author wrote (IV.1), and `pub def handle(ctx :
  Context)` resolves `Context` through a `using` further up the file. The
  annotation travels, so what resolves it has to travel with it.
- **Exported constants**, with values where a value can appear in a type.

**A block parameter is a parameter (R-2).** An exported `def` that takes a
block has to say what the block is: `pub def namespace(path : String, &)` says
a block arrives and nothing about it. Inside the module that is enough, because
the `yield` is right there. Through an artifact it is not — the body stays
behind, and what the block receives and returns is in it. Refused where the
module is compiled rather than where it is read, because that is where the
author can fix it.

The count that decided it: **one exported signature in the samples out of about
eighty** — Kemal's `Router#namespace`, which is also the case no annotation can
express yet, since `with sub_router yield` changes what `self` means inside the
block. So the rule costs one method today, and the method it costs is one whose
type nothing in the language can currently write down. Whether `with … yield`
gets a notation is open; until it does, a module that wants one keeps it
unexported.

**Out, deliberately:**

- Bodies of ordinary `pub` functions.
- Everything private — types, methods, fields not exposed.
- Anything that would let a consumer come to depend on an implementation detail.

**The two exceptions, both of which cost something:**

1. **Macro bodies.** `derive JSON` runs in the module declaring the type
   (II.4), so that module needs `std/json`'s macro body in order to run it.
   Macros are compile-time code; shipping them is loading a plugin, not reading
   an implementation.
2. **`@[Monomorphize]` bodies.** The consumer specialises them, so it needs the
   body. This is the (b) path from II.6 and it is where incrementality is at
   risk — see IV.3.

   **Built, and wider than the annotation suggests.** The set is not the items
   somebody marked: it is every method a consumer has to compile, which the
   compiler can work out for itself. A generic type's methods, because
   instantiations belong to whoever writes them; a trait's defaults, because
   they are stencilled onto the implementing type; and an impl's methods
   *unless* its target is a non-generic type this module declares, because
   otherwise they land in a unit the artifact cannot carry. `@[Monomorphize]`
   remains the annotation for choosing to specialise something that would
   otherwise be a dictionary call (II.6); it is not what decides whether a body
   travels. See IV.1g.

### IV.3 Hashing — the part that decides whether builds are actually incremental

**The property that matters: changing a function body must not change the
interface hash.** If it does, every dependent rebuilds and the entire benefit
evaporates.

Three hashes, not one:

| Hash | Covers | Changing it invalidates |
|---|---|---|
| **Interface** | exported signatures, layouts, type descriptors, trait declarations, impl records, exported constant types | every dependent must re-typecheck |
| **Implementation** | macro bodies, `@[Monomorphize]` bodies | only dependents that actually expand or specialise those items; no re-typechecking |
| **Private** | everything else — private types, all ordinary bodies | nothing outside this module; dependents relink but do not recompile |

Worked through:

- Edit a private helper → private hash only → this module rebuilds, nothing else.
- Edit a `pub def` body → private hash → this module rebuilds; dependents relink.
- Change a `pub def` signature → interface hash → dependents re-typecheck.
- Edit `@[Monomorphize] def map`'s body → implementation hash → callers of `map`
  re-codegen, but do not re-typecheck.

**This makes the real price of `@[Monomorphize]` visible.** It is not only "more
code generated" — it puts the body in the metadata, so **editing a monomorphised
function rebuilds everything that uses it.** That is the mechanism behind Rust's
slow incremental builds, and iyi imports it deliberately, in exchange for speed
on the hot path. Without the interface/implementation split it would poison
incrementality outright.

**Cache key** for a module: its own source hash, plus the interface hashes of
all transitive imports, plus compiler version, target triple and build flags.

**Granularity — module-level, for Draft 0.** Adding an unused `pub def`
invalidates dependents that never call it. That is pessimistic, and acceptable,
because what re-typechecking costs is a metadata read, not body analysis — the
expensive thing is already avoided. Per-declaration hashing with used-symbol
tracking is the known refinement (this is what salsa does) and should wait until
measurement says module-level is the bottleneck.

### IV.4 A result: coherence needs no global check

R-3 says an `impl Trait for Type` must live in the module defining the trait or
the type. Separate compilation raises the obvious worry: if module T and module
Y each define `impl Show for Foo`, neither can see the other, and the clash is
only discovered at link time — or never.

**It cannot happen.** Suppose trait `Show` is in module T and type `Foo` in
module Y. The impl may live in T or in Y.

- For T to define it, T must name `Foo`, so T imports Y.
- For Y to define it, Y must name `Show`, so Y imports T.
- Both would mean T imports Y and Y imports T — a cycle, which R-1 forbids.

So at most one module can define any given impl, **by construction**. The
compiler now refuses the cycle rather than leaving that step of the argument to
the load order that happened to hide one module's names from the other (III.5
rule 1).

The argument needs both T and Y to exist, and the build found the case where
neither does: a trait the compiler owns, or a prelude type, belongs to no
module. Taking the top level to be a module in their place is what broke this —
every module counts as inside it, so nothing was ruled out and any number of
modules could write `impl Error for String`. The top level is therefore not a
module (III.1.1): where a side has no module, that side cannot be satisfied,
and an impl with no module on either side is rejected wherever it is written.
That restores the premise rather than adding a rule.

The DAG and the orphan rule together make duplicate impls unrepresentable, and
coherence is checkable locally from the impl records in IV.2. No global pass, no
link-time surprise, no cost at build time.

This is the payoff for accepting R-3's restriction, and it is worth stating
plainly because it is not obvious that the orphan rule buys anything beyond
knowing a type's method set.

### IV.6 Notes from implementing the parser

Three things only surfaced once the syntax was fed to a real lexer. Recorded
because they are the class of problem a spec cannot find by reasoning.

**1. `/` in module paths collides with regex literals.** After an identifier,
Crystal's lexer treats `/` as the start of a regex, so `module app/user` lexes as
`app` followed by `DELIMITER_START`. Module paths are the one place `/` separates
rather than divides, so the parser suppresses regex mode while reading a path.
Go sidesteps this by putting import paths in string literals; Rust by using
`::`. Keeping `/` is a deliberate choice — it mirrors the filesystem — and it
costs a two-line workaround.

**2. `abstract def` for trait requirements.** See II.6; a bare signature is not
distinguishable from a default method without unbounded lookahead.

**3. Module paths are absolute, resolved from the project root.** Not relative
to the importing file. This only surfaced when a module two levels deep
imported a sibling: a relative reading resolved `app/greeter` against
`app/`, looked for `app/app/greeter`, and failed. The deeper point is that a
relative reading makes a path's meaning depend on where it is written, so two
files can disagree about what `app/greeter` refers to — which defeats the
purpose of having module identity at all. Go takes the same position. Until iyi
has a manifest, the project root is the directory of the entry file.

**4. Namespacing makes `using` mandatory, not a convenience.** II.3 presented
`using` as the thing that keeps DSL-shaped libraries writable. Implementing
namespaces showed it is more basic than that: the moment `module app/greeter`
actually scoped its contents, every cross-module reference broke, and the
working test had to be rewritten to
`impl App::Greeter::Greet for User` / `App::Greeter.polite(name)`. Without
`using`, ordinary multi-module code is unbearable, not merely verbose.

**5. Module functions need `extend self`.** A `pub def` at module level is a
function of the module, not an instance method of a mixin — iyi modules are
compilation units, not mixins. The desugar inserts `extend self` so
`App::Greeter.polite` resolves.

**6. Declaring a module and naming one. SETTLED — the mismatch stays, and is
made reversible. Built.** A module is declared lowercase (`module app/greeter`)
but reached capitalised (`App::Greeter`), because Crystal type names must be
constants. Three answers were available: accept the mismatch, adopt Go's
convention where the last path segment is the name, or teach the type system
lowercase module names. The third is the better language and does not fit
0.1.0; the second replaces a cosmetic problem with a real one, since
`app/greeter` and `web/greeter` would then be one name.

So the mismatch stays, and stops being a wart by being made **reversible**: a
path segment is `[a-z][a-z0-9]*` with single `_` between groups, checked in
`Parser#parse_module_path`, which is the one gate `module`, `import` and
`using` all pass through. `camelcase` upper-cases the first character of each
underscore-separated group and drops the underscores, so a name splits back
into a path at every upper-case letter, and path and name determine each other.

**"Lowercase snake_case" was not the rule, and finding that out is why it was
checked rather than asserted.** `camelcase` drops an underscore that precedes a
digit, so `v_1` and `v1` both give `V1` — two paths, one module, a collision
that survives any amount of care about naming style. Doubled, leading and
trailing underscores collide the same way (`my__greeter` with `my_greeter`,
`my_` with `my`). Requiring each group to begin with a letter removes all four
cases at once.

**7. New keywords are cheap, but not free.** `trait`, `impl`, `pub`, `import`
and `using` were added to the lexer with no regressions — `trailing`,
`implements`, `public`, `usingx` and `impl_` all still lex as identifiers. But
`impl` was in use as a local variable in two compiler tool files, which had to be
renamed. Every keyword iyi adds is a name taken away from every program; the
count should stay small.

### IV.5 Versioning

Format version in the header. **Compiler version must match exactly** for
Draft 0 — a `.iyimod` built by a different compiler is rejected and rebuilt, not
migrated. Cross-version metadata compatibility is a large, permanent surface and
there is no reason to take it on before 1.0.

---

## Part V — Not yet specified

Named honestly, so nobody mistakes this draft for complete.

1. ~~Export metadata format.~~ **Specified in Part IV.** Remaining sub-question:
   the concrete binary encoding, which is engineering rather than design.
2. ~~Trait generics and associated types.~~ **Settled by II.6** — both forms
   exist; associated types for single-answer traits, parameters where multiple
   impls are the point.
3. ~~Trait default methods.~~ **Settled by II.6** — traits supply bodies, with
   their own type parameters and conditional `where` bounds.
4. ~~**Module initialisation order.**~~ **Specified in III.5** — DAG order, a
   relative order between independent modules that is unobservable rather than
   merely unspecified, no `init()`, no import for side effects, and
   initialisation that may not fail. All but "no import for side effects" are
   built, the shuffle that keeps the unobservable order unobservable included.
   That last one is the only rule here with a cost and no measurement.
5. ~~**Concurrency semantics.**~~ **Specified in III.4** — structured
   concurrency so a leak is unrepresentable, cancellation owned by the scope
   rather than threaded through signatures, task failure as an ordinary error
   member, and a `Share` marker that makes a data race a compile error. The
   module-level state question the Kemal port flagged is answered by III.4.5:
   the combination does not compile. Proposed, not built, and III.4.7 names the
   count that has to come first.
6. ~~**Macro cost.**~~ **Measured — see II.10.** Expansion is not a compile-time
   cost worth policing: a template macro is indistinguishable from writing the
   code, and a computing macro costs less per method than defining the method
   does. `macro_run` is the exception, at a fixed +7.4 s per distinct script on
   a cold build. The measurement record has no gaps left.
7. ~~Stdlib naming convention.~~ **Settled by III.1.7(A)** — `!` has left
   identifiers and the mutating/non-mutating pair is `sort` / `sorted`. Settled
   while no stdlib code existed yet, which was the whole point: it is a
   convention the entire library has to be designed around from the first
   commit, and it is now enforced by the compiler rather than left to style.
8. **`defer` semantics.** ~~Ordering of multiple `defer`s in a scope, and
   whether a `defer` may itself propagate with `!`.~~ **Both answered as Go
   answers them, LIFO and no** — LIFO because it is the reverse of acquisition
   order, and no because a `defer` runs while the function is already returning
   (Appendix B #7). Both are built (III.1.4), along with one departure from Go:
   the scope is the block, not the function.

---

## Appendix — What measurement settled

For traceability, since several rules here rest on numbers rather than taste.

| Claim | Evidence |
|---|---|
| Separate compilation is the main prize | 1000 typed functions cost +0.08 s; ~95% of non-LLVM work is fixed prelude tax |
| A cached prelude is worth 3.4×, not 20× | fork probe: 1.58 s → 0.47 s front end; 0.09 s if the prelude did not exist (IV.1a) |
| The artifact is not the whole job | with the prelude pre-analysed, class-var initializers and `main` are 90% of what is left, because they still walk the prelude (IV.1a) |
| Prelude-aware passes are worth another 10× | a front end that never walks the prelude runs `hello.iyi` in 0.049 s vs 1.58 s, and emits an object with an identical symbol table (IV.1a) |
| The front end and codegen need the prelude for different reasons | codegen emits `fun`s by walking the AST, so the prelude's tree must reach it regardless; only the front end's need is removed by caching analysis (IV.1a) |
| Half the top-level pass is the parser | 304 prelude files, 107,719 lines: 0.57 s parse, 0.54 s visit |
| Open classes are the blocker | 77 of 484 types reopened across module boundaries; `String` by five modules |
| Traits are a viable replacement | Kemal router ports at +4% code size, structure intact |
| `using` is required, not optional | Kemal's DSL is unwritable without it |
| Dictionaries pay off at compile time | 46.6% of instantiations collapse (compiler), 47.7% (app-shaped code) |
| Dictionaries cost ~3–4 cycles per call | 17.5× on a vectorisable loop, 1.21× where neither side vectorises, 1.00× with real work per element |
| `macro_run` must go | +7.4 s per distinct script on a cold build, memoised per script but not amortised across scripts; two scripts cost twice (II.10) |
| Macro expansion is not a compile-time cost | a template macro runs at 1.00–1.05× hand-written code; a computing macro adds ~9 µs per method against the ~18 µs the method costs anyway (II.10) |
| `method_missing` is safe to cut | one occurrence in stdlib, zero in Kemal |
| Traits can carry the stdlib | `Enumerable` ported and running: 57 of its 71 method names on one `each`, implemented for two element types, every method called (`samples/iyi/std/enumerable.iyi`) |
| `Share` prices a style rather than failing | clean-sheet iyi code is 77% shareable as written and 100% given an immutable collection; the compiler, built as a mutable workspace, is 38.5% and stays there (III.4.7) |
| Module-level mutable state is already rare | 3 of 483 compiler types hold a class variable, so III.4.5 costs almost nothing |
| Coherence costs nothing at build time | the import DAG plus the orphan rule make duplicate impls unrepresentable (IV.4) |
| The gap to Go is the warm build, and it is 11× | `hello`: cold 2.20 s vs Go's 1.98 s, warm 1.96 s vs Go's 0.18 s. Crystal's cache holds codegen only, so the 1.32 s front end is paid on every build (`bench/build_speed.py`) |
| A first release's prelude is ~3.5k lines | Crystal 0.1.0 shipped 8,161 lines of library, 3,551 of it the core that a prelude is; the rest is `json`/`yaml`/`http` |
| Self-hosting only gets more expensive | Crystal self-hosted at 24,984 lines of compiler and 8,161 of library, before its 0.1.0; iyi's fork starts at 95,010 and 196,217 (Appendix B.2) |
| The path/name mapping needed more than snake_case | `camelcase` drops an underscore before a digit, so `v_1` and `v1` both give `V1`; requiring each group to start with a letter removes that and three sibling collisions (IV.6 #6) |

## Appendix B — Decisions awaiting your call

| # | Decision | Recommendation |
|---|---|---|
| 1 | Errors as unions at all (III.1) | yes — biggest departure from Ruby feel, so it is a taste call |
| 2 | ~~`!` in identifiers vs `!` as propagation (III.1.7)~~ | **Decided: A** — `!` dropped from identifiers, `sort`/`sorted` adopted, enforced by the compiler |
| 3 | ~~Implicit error conversion (III.1.6)~~ | **Decided: no, and not on a schedule** — the signature is the error set; a conversion the reader cannot see takes that away |
| 4 | ~~Nil-propagation operator (III.1.5)~~ | **Decided: no, and not on a schedule** — a second propagation channel ends by making `Nil` an error, which III.1.5 exists to prevent |
| 5 | `pub using` re-export (II.3) | no, for Draft 0 |
| 6 | `@[Monomorphize]` on stdlib trait defaults (II.6) | yes — mark `each`/`map`/`select`/`reduce`, stencil the rest. Accepts that the library author owns a per-method performance decision |
| 7 | ~~`!` inside a `defer` (III.1.4, V.8)~~ | **Decided: no** — a `defer` runs while the function is already returning, so propagating from one needs error-during-error semantics |
| 8 | Structured concurrency only, no bare spawn (III.4.1) | yes — it is `defer` applied to a task set, so it costs no new mechanism, and it makes Go's commonest bug unrepresentable. The price is that a task cannot outlive its scope, which is a taste call |
| 9 | ~~`Share` marker vs Erlang-style no sharing (III.4.4)~~ | **Decided: `Share`, on the count** — III.4.7 found the feared class empty and clean-sheet iyi code 77% shareable as written, 100% given a shareable immutable collection. That collection is now a stdlib obligation, not a nicety |
| 10 | ~~**Is iyi ever meant to be self-hosted?**~~ | **Decided: no.** iyi's compiler is and remains a Crystal program. The language's claim is what it compiles, not what compiles it. See B.2 |

### B.2 — The one decision the fork already made — **SETTLED: not a self-hosting project**

Crystal's compiler was written in Crystal before its 0.1.0, when the compiler
was 24,984 lines and the library 8,161. iyi begins from a fork: 95,010 lines of
compiler and 196,217 of library, none of it written in iyi, and none of it
compilable by iyi's own rules — the Appendix's own count says 77 of 484 types
are reopened across module boundaries, `String` by five modules.

The fork was the right call and it is why iyi has a working backend, a GC and a
measured thesis at 75 commits. It also bought that with something, and the
something is this: **self-hosting is the one cost that only rises.** Crystal
paid it at 33k lines total. iyi would pay it at 291k, against rules that forbid
the style most of those lines are written in.

So this is not a task that gets scheduled later; it is a door that is already
mostly shut, and the honest thing is to say so rather than leave it implied.
**Settled: iyi is not a self-hosting project.** Its compiler is and remains a
Crystal program, and the language's claim is what it compiles rather than what
compiles it. Go
is again the evidence for why that is survivable: `gc` stayed a C compiler
until Go 1.5 in 2015, nearly six years after the language was announced and
four point releases into Go 1, and nobody held it against the language.

The alternative — deciding that self-hosting matters — would have changed the
plan rather than added to it: it would make the compiler's own shape a design
input from here on, and III.4.7's measurement that the compiler is 38.5%
shareable *and stays there* is the first thing it would have collided with.
Deciding it now costs nothing; deciding it after the library exists would have
cost the library.

### B.1 — Why #3, #4 and #7 are one decision

They are three requests for the same thing: **more reach for `!`**. Each is
individually reasonable and the three of them together are how this design
fails, so it is worth writing down once what they have in common rather than
answering each on its own merits.

`!` does exactly one thing: return early. It does not convert, does not widen,
does not reach into a second kind of absence, and does not run during unwind.
That is the whole of it, and the value of the design is in what the operator
**refuses** to do, not in what it does — because everything it refuses is a way
for a function's real error set to stop being the one written in its signature.

Go's own answer to this question is the evidence. The `try` proposal
(golang/go#32437, 2019) was not declined for being hard to implement. It was
declined because it hid control flow and made adding context to an error worse,
and Go took error *wrapping* instead. That is a language with the same taste as
this one deciding that the operator was the wrong place to spend the budget.

Taken one at a time:

- **#3, implicit conversion.** This is the decision that separates this design
  from Rust's. `?` plus `From` means the set of errors a function returns is
  computed by a trait resolution the reader cannot see, which is why that
  ecosystem grew libraries whose entire job is to make error types writable.
  Here the signature is the truth, and it stays the truth only if nothing
  silently rewrites an error on the way out. The replacement is not a
  conversion mechanism: error sets are aliases (III.1.2), so widening a return
  type covers most of what conversion is asked for, and it is free. Genuine
  conversion — deliberately *hiding* one error behind another — is rare, should
  look rare, and is an ordinary function call.
- **#4, nil propagation.** `T?` and error unions are different questions, and
  III.1.5 keeps them different. A `?`-propagating operator would put them in the
  same shape, and the pressure would then be to unify them — at which point
  `Nil` implements `Error` and the distinction is gone. Flow typing already
  handles absence, and it is the better tool: it forces the branch to be written
  where the absence means something, which is the whole reason absence is not an
  error.
- **#7, `!` in a `defer`.** A `defer` body runs while the function has already
  decided to return, and possibly while it is carrying an error of its own.
  Propagating a second error from there is the error-during-error problem, which
  is the ugliest corner of every language that has taken it on. A `defer` body
  handles its own failure, explicitly — `.or_panic` or ignore it.

None of the three is blocked on anything. They are not deferred to Draft 1; they
are answered.
