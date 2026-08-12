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

---

## Part III — Open questions, with recommendations

### III.1 Errors — **DECIDED (Appendix B #1: yes), being built**

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

**Built.** `Error` is created by the compiler rather than declared in the
prelude, because the compiler has to recognise this exact trait — `!`, `.or` and
`.or_panic` all ask whether a member implements it — and a name the prelude
happened to define could be shadowed or replaced. Nothing else about it is
special: a module writes `impl Error for IOError` like any other impl, and the
`message` requirement is checked like any other.

The type side needed nothing else. Error unions are ordinary unions, and III.1.3
is already true: dropping a branch from a `case` over one is reported as `case is
not exhaustive`. `T?` is untouched, since `Nil` does not implement `Error`.

Two things the build found:

- **`it` is not bound in a `case` branch.** The examples in this section write
  `in IOError then log(it)`; `it` is Crystal's block-parameter shorthand and
  means nothing in a `case`. Either the examples take a variable, or `case`
  learns to bind one. The examples below are written the second way and are
  aspirational until it does.
- **The orphan rule is vacuous for a top-level trait.** `Error` has no module,
  and coherence is satisfied by being inside the trait's module *or* the type's
  — where the trait's module is the top level, everyone is inside it. So
  `impl Error for String` is accepted from any module, and two modules could
  both write it. Narrow today, because `Error` is the only trait with no module,
  but it is the orphan rule not holding.

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

### III.3 `method_missing` — **PROPOSED: cut it**

It requires an open method set, which R-3 closes by construction.

Grounded rather than asserted: in the Crystal standard library `method_missing`
appears **once**, as the hook definition in `object.cr`. **Kemal does not use it
at all.** Meanwhile `responds_to?` — the static alternative — appears across 34
files. The dynamic escape hatch is close to unused; the static one is what
people actually reach for.

Cut it. Keep compile-time `responds_to?`.

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
| Mono bodies | serialised typed IR for `@[Monomorphize]` items |
| Object code | machine code for this module's own definitions |

Binary, for read speed. A `iyi mod dump` producing text is required, not
optional — an opaque cache format is one nobody can debug.

**Target:** reading the prelude's `.iyimod` should cost single-digit
milliseconds, against the **~1.0 s** its top-level analysis costs today —
measured, not estimated, and 2× the 0.5 s this section claimed before anyone
had run the experiment. See IV.1a for what that does and does not buy.

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
- **Layout templates.** Size, alignment, and pointer map — expressed as a
  *function of the type parameters' shapes*, not a fixed layout. `Array(T)` is
  three words regardless of `T`; `Tuple(Int32, String)` is not. R-4 needs the
  template to stencil at any shape.
- **Type descriptors.** A runtime type id per exported type. II.6 established
  that dictionaries carry type identity, not just pointer maps, because
  `select(type : U.class)` filters by runtime type.
- **Signatures** of `pub` functions and methods. Parameters, return type, and
  the `where` bounds from II.6.
- **Trait declarations.** Required methods, associated types, and the
  *signatures* of default methods.
- **Impl records.** Every `(Trait, Type)` pair this module provides. This is
  what lets a consumer answer "does `Customer` implement `ToJSON`?" without
  reading `Customer`, which II.4 depends on.
- **Exported constants**, with values where a value can appear in a type.

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

So at most one module can define any given impl, **by construction**. The DAG
and the orphan rule together make duplicate impls unrepresentable, and
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

**6. Declaring a module and naming one do not match yet.** A module is declared
lowercase (`module app/greeter`) but reached capitalised (`App::Greeter`),
because Crystal type names must be constants. The implementation capitalises
each path segment. This is a wart the spec has to settle: either accept the
mismatch, adopt Go's convention where the last path segment is the name, or
teach the type system lowercase module names.

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
4. **Module initialisation order.** Kemal registers routes as a side effect of
   top-level calls. Legal, but the ordering guarantees across a module DAG need
   stating. Go's `init()` is the reference.
5. **Concurrency semantics.** `Channel(T)` and `Fiber` carry over from Crystal,
   but their interaction with module-level mutable state — which the Kemal port
   flagged as a smell worth fixing — is unspecified.
6. **Macro cost.** Still unmeasured. The one gap in the measurement record; the
   attempt to isolate it was invalid because the test program never called the
   generated methods.
7. ~~Stdlib naming convention.~~ **Settled by III.1.7(A)** — `!` has left
   identifiers and the mutating/non-mutating pair is `sort` / `sorted`. Settled
   while no stdlib code existed yet, which was the whole point: it is a
   convention the entire library has to be designed around from the first
   commit, and it is now enforced by the compiler rather than left to style.
8. **`defer` semantics.** Ordering of multiple `defer`s in a scope, and whether
   a `defer` may itself propagate with `!`. Go's answers (LIFO; no) are probably
   right but are not automatic here.

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
| `macro_run` must go | 21% of a cold build from one call site |
| `method_missing` is safe to cut | one occurrence in stdlib, zero in Kemal |
| Traits can carry the stdlib | `Enumerable` ported and running: 57 of its 71 method names on one `each`, implemented for two element types, every method called (`samples/iyi/std/enumerable.iyi`) |
| Coherence costs nothing at build time | the import DAG plus the orphan rule make duplicate impls unrepresentable (IV.4) |

## Appendix B — Decisions awaiting your call

| # | Decision | Recommendation |
|---|---|---|
| 1 | Errors as unions at all (III.1) | yes — biggest departure from Ruby feel, so it is a taste call |
| 2 | ~~`!` in identifiers vs `!` as propagation (III.1.7)~~ | **Decided: A** — `!` dropped from identifiers, `sort`/`sorted` adopted, enforced by the compiler |
| 3 | Implicit error conversion (III.1.6) | no, for Draft 0 |
| 4 | Nil-propagation operator (III.1.5) | not in Draft 0 |
| 5 | `pub using` re-export (II.3) | no, for Draft 0 |
| 6 | `@[Monomorphize]` on stdlib trait defaults (II.6) | yes — mark `each`/`map`/`select`/`reduce`, stencil the rest. Accepts that the library author owns a per-method performance decision |
