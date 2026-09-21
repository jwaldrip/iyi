# Self-hosting: where the port is

An iyi program that compiles iyi. This directory is the front end being
written in the language it compiles, one slice at a time, with each slice
diffed against the compiler that exists.

## How it is checked

Not by reading it. `parser/oracle.cr` prints the tree the current parser
builds as a canonical S-expression; `parser/parser.iyi` prints the same
shape from its own tree; `parser/diff.sh` compares them.

```
bash selfhost/parser/diff.sh                      # the fixtures
bash selfhost/parser/diff.sh samples/iyi/*.iyi    # the real corpus
bash selfhost/parser/where.sh samples/iyi/*.iyi   # how far each one agrees
```

`diff.sh` is the gate: it exits non-zero when anything differs. `where.sh`
is the worklist: whole-file agreement moves one file at a time and hides a
slice that fixed nine tenths of twenty files, so it reports the column
where each file first disagrees and what the oracle had there.

Three things about the harness are load-bearing, because each one was
wrong first and made the port look better or worse than it was:

- The oracle sets the **filename**, because `Lexer#filename=` is what turns
  iyi mode on. Without it an `.iyi` file is parsed as Crystal, and
  `errors.iyi` died on the `!` that propagates.
- An oracle that prints **nothing** is its own row. Counting it as a
  difference made the current parser refusing a file look like the port
  disagreeing about it.
- The oracle prints **branches and members**, not just node names. `(if)`
  on its own lets a port that mis-read a condition agree with it.

## Where it is

Measured, not estimated: **all 27** files in `samples/iyi` produce a tree
identical to the current parser's.

```
bash selfhost/parser/diff.sh samples/iyi/*.iyi
  agree 27, differ 0, no oracle 0
```

The lexer slice (`lexer/`) agrees with the current lexer token for token
on **116 files**: every sample, every standard library file, the
prelude, and the port's own source.

## What the port carries

Module headers and the `Samples::InitOrder` camelisation; files with no
header at all; `import` hoisted when it leads and left in place when it
does not; `using`. `def` with typed arguments, return types, `forall`,
`abstract`, and the `@x` argument that is also an assignment. `trait`,
`struct`, `class` and `impl`, with type parameters on all of them.
Instance variables and field declarations. Types as a thing distinct from
expressions: generics, unions. `if`, `unless` as its own node, `elsif`,
`while`, `until`, the trailing forms, `return`, `&&` and `||` as the
short-circuit nodes they are. Calls with and without parentheses, chains,
`a[i]`, `a[i]?`, `a[i] = v`, blocks in both spellings. Literals: integer,
string, interpolated string, char, array, hash, tuple, range, `true`,
`false`, `nil`, and the empty forms that say what they are in an `of`
clause rather than in their braces.

## The next slices

Three corpora are closed: the samples, the prelude, and the standard
library. The parser also reproduces its own source, which is the largest
single iyi file there is. What no corpus exercises is what remains:
heredocs, regex literals, `lib` and `fun` bodies, `with ... yield`, and
the macro language itself, which every corpus skips to its `{% end %}`
rather than parsing.

## The semantic pass

`semantic/oracle.cr` is the first slice's oracle, and the slice is what a
file *declares*: for each type, its kind, its path, its parameters and its
methods. It already says something the parser cannot, which is the point
of the stage: a `struct Box` with `impl Show for Box` beside it answers
`show`, because the impl attached it.

```
bin/crystal run selfhost/semantic/oracle.cr -- samples/iyi/hello.iyi
```

It runs the pass on one file with no imports resolved, so **23 of 27**
samples answer and four do not. Those four are the measure of what
resolving imports would add, and they are reported rather than skipped.
The port is `semantic/declare.iyi`; its measured state is below.

After the parser: the semantic pass, then codegen, then the bootstrap,
each differentially tested the same way. The bootstrap is the acceptance
test and it is available from the first day the port parses anything: the
Crystal-written compiler and the iyi-written one compile the same corpus
and must agree.

## The prelude

`samples/iyi` was written for this language, so it says only what the
language was built to say. `src/iyi` was not: it is the prelude, written
before the port existed, and it is the second corpus.

    bash selfhost/parser/where.sh src/iyi/*.iyi

Measured: **17 of 17 files agree**. The second corpus closed the shapes the
samples never needed: compiler questions (`pointerof`, `sizeof`,
`instance_sizeof`), casts, `yield`, splats, symbols, macro loops,
keyword-named parameters, defaults, pointer types, uninitialized variables,
forwarded blocks, wrapping arithmetic, base-prefixed numbers, visibility
modifiers, and string escapes as values rather than spelling.

Two defects were in the harness rather than the language. A private method
whose body took a `do` block let the block's `end` stand in for the
method's, and `getter end : E` was mistaken for a block boundary. The full
corpus, rather than a hand-picked fixture, is what exposed both.

## The standard library

`src/std` is the third corpus and the one nobody wrote with a port in
mind: 67 files, an order of magnitude more code than the prelude, and the
only corpus large enough that a first-divergence column was the only
usable worklist.

    bash selfhost/parser/where.sh src/std/*.iyi

Measured: **all 67 files agree**, from 16 when the corpus was first run.
One parser rule moved more than a dozen files at a time, which is why the
work was ordered by shared class rather than by file: absolute paths
(`::Atomic`), imports hoisted out of a file with no module header,
visibility on a declaration that is not a `def`, multiple assignment,
proc notation in a restriction, enum bodies that carry methods, the
semicolon as a statement separator, compound assignment, splat and
double-splat parameters and types, typed empty arrays, and multiline
argument lists.

Three of the last six were defects in the port's own reading rather than
missing grammar, and each one printed a plausible tree rather than an
error:

- A `do` block counted `end` without knowing that `{% end %}` closes a
  macro conditional, so a block containing one finished an `end` early.
  The block then swallowed the method's `end`, the method closed, its
  locals went out of scope, and a variable two lines later printed as a
  call. The fix was to read a `do` block with the same reader every other
  body already used.
- `yield (a | b).unsafe_chr` is a yield of one argument and
  `yield(a, b) > 0` is a comparison of what the block answered. The
  difference is the space, so the parentheses are the argument list only
  when they are adjacent to the word.
- A name declared with a type is a local inside a method and a field
  outside one. Registering both made every later read of a field print as
  a variable, in five files that had agreed before.

The corpus also closed `%w(...)` as one literal, `private record Name,`
continuing onto the next line, and a union alias wrapping after a `|`.
With those, the parser reproduces the tree of its own source: 3,597 lines
of iyi, printed identically by the compiler that exists and by the port.

`where.sh` is the worklist and `diff.sh` is the gate, and the gate takes
the same corpus:

    bash selfhost/parser/diff.sh src/std/*.iyi

It is load-bearing on this corpus too. Dropping the adjacency test that
separates `yield (a).b` from `yield(a).b` turns `agree 1` into
`differ 1` on `src/iyi/string.iyi`, and restoring the file byte-for-byte
turns it back.

## The declaration pass

`selfhost/semantic/declare.iyi` is the first semantic slice written in
iyi: what a file declares. It imports the parser, walks its tree, and
prints the same shape `selfhost/semantic/oracle.cr` reads off the real
top-level pass.

    bash selfhost/semantic/diff.sh

Measured: **23 agree, 0 differ, 4 with no oracle**. The four are
`collections`, `immutable`, `std_text` and `webapp`, where the pass
itself refuses the file because it resolves no imports; they are
reported rather than skipped so the number says what it covers.

Three rules in the port are the compiler's rather than the language's,
and each was read off the oracle rather than guessed:

* a trait that declares an associated type is a generic module, and
  prints as one;
* a generic class prints its parameters twice, in its name and again as
  its parameter list, and a generic module only once;
* an `impl`'s methods belong to the type it is for. `impl Show for
  Box(T)` puts `show` on `Box`.

Getting here split `selfhost/parser/parser.iyi` into a library and the
command that was at the bottom of it, `selfhost/parser/main.iyi`, since
a program cannot be imported and the semantic pass reads the same tree.

The gate is load-bearing: changing one method name the pass reports
turns `agree 1` into `differ 1`, and restoring the file byte-for-byte
turns it back.

### The prelude, declared

The samples corpus was written for this language and the prelude was
not, so the declaration pass gets the same second corpus the parser did:

    bash selfhost/semantic/diff.sh src/iyi/*.iyi

Measured: **13 agree, 2 differ, 2 with no oracle**, from 4 agreeing when
the corpus was first run. What it closed is what a declaration is, as
opposed to what a file says:

* A private method is a method the type has. The parser used to count
  `private def` to its `end` and throw the declaration away, so the
  modifier now carries it and the shape still prints the modifier alone.
* `def self.x` belongs to the type and `def x` to its instances. They
  print the same and land on different types, so the node carries the
  receiver the shape does not.
* An `alias` brings a type into being, and the pass reports it as one.
* `struct Int32` in the prelude does not build a struct: the compiler
  already holds that type and reports it by its own kind. The same is
  true of `Bool`, `Nil`, `Char`, `Symbol` and `Class`, and of `Tuple`
  and `Proc`, which the compiler holds with parameters the prelude does
  not write down.
* A struct answers `new`, so the compiler writes the `initialize` that
  `new` calls when the struct declares none. `Reference` is the root the
  compiler builds the same way.

Parsing a private declaration instead of counting over it found a
grammar gap the corpus had been hiding: `escape =` with its value on the
next line was read as an assignment of nothing followed by a statement,
in `src/std/eiy.iyi`, inside a private method nothing had parsed before.

The two that differ are both macro expansion, and neither is this
slice's: `primitives.iyi` writes six of `Char`'s methods with a
`{% for %}` loop, and `prelude.iyi` uses `property`, whose definition
arrives through a `require` this pass does not resolve. The macro
language is the next slice and these two are its measure.

### The standard library, declared

    bash selfhost/semantic/diff.sh src/std/*.iyi

Measured: **29 agree, 6 differ, 32 with no oracle**, from 13 agreeing
when the corpus was first run. Thirty-two files answer nothing because
the pass raises on a name an import would have brought, and they are
reported rather than skipped so the number says what it covers.

Two rules came out of this corpus, and both are about which type a
declaration names rather than what is in it:

* `struct ::Bool` is the root's type and `struct Bool` inside a module
  is that module's. Eleven files write the first and the port read them
  all as the second, so `Bool` was reported as `Std::Bool::Bool` and the
  prelude's type was never touched. The parser reads the marker and
  dropped it, because the canonical shape prints the path without it;
  now the node carries it.
* A file that opens `Std::File` and imports `std/path` did not bring
  `Std` into being, and the pass reports only what this file declared:
  such a file's own module is invisible to it and so is everything
  inside it, leaving `class ::File` and nothing else. A file that shares
  no root with what it imports, `samples/hello` importing `app/greeter`,
  declares its modules and their contents as usual. Getting this wrong
  in the other direction cost the samples corpus five files before the
  rule was measured rather than guessed.

`EOF` is one word: an underscore rule that broke before every capital
spelled the enum member `e_o_f?` where the compiler spells it `eof?`.
An enum body holds methods as well as members, and `NamedTuple` is
another type the compiler holds with parameters the source does not
write down.

What the six that differ measure is two things this pass did not do at
the time: five of them expand macros, and the section below closes
three of those. The sixth, `big.iyi`, writes no macro at all. It
reopens `Int32`, and the compiler reports every method that type has,
including the tower `std/int` writes, so reporting them means loading
what the file imports.

### Macros

A macro body is not iyi until it has run. `def add_{{suffix}}` is not a
method declaration and `{% if flag?(:darwin) %}` is not a statement, so
nothing downstream can read either until expansion. Crystal expands a
macro into source and parses the result, and `selfhost/macro/expand.iyi`
does the same for the shapes the corpora write:

    bin/iyi build -o macro selfhost/macro/main.iyi && ./macro src/std/errno.iyi

It carries `{% if %}`, `{% elsif %}`, `{% else %}`, `{% unless %}`,
`{% begin %}`, `{% for %}` over a literal list or map or over a name
bound above it, `{% name = ... %}`, and `{{ name }}` substitution. What
it cannot evaluate it drops, which is what the reader before it did with
every macro: a region that cannot be evaluated has no declarations
rather than wrong ones. Its flags come from its own `flag?`, because the
pass is built by the compiler it is measured against.

The declaration pass reads the file twice, and the second reading is
where the rule lives. A macro's *methods* land on a type the file
declared and are reported; the *type* a macro writes is not reported at
all, because its home is the expansion rather than the file. So
`errno.iyi` gains the members its platform branch lists and does not
gain a constant for each of them, and `primitives.iyi` gains the six
operators a loop writes onto `Char` without the file appearing to
declare `Int32`.

This closed `atomic.iyi`, `errno.iyi` and `primitives.iyi`: the prelude
corpus went to **14 agree, 1 differ** and the standard library to
**31 agree, 4 differ**. The expansion is load-bearing: making the map
loop run no times turns `atomic.iyi` from `agree 1` into `differ 1`, and
restoring the file byte-for-byte turns it back.

The four that remain need what a macro cannot give them. `named_tuple`
is missing exactly the methods `tuple.iyi` declares, `traits` and
`float` are missing the integer tower that `std/int` writes, and
`big.iyi` imports `std/traits`, which imports both. They are one
capability away, and it is the same one the bootstrap needs: loading
what a file imports.

### What a file imports, and what it requires

Both corpora are closed now, and they were closed by two different
edges. An `import` is a module edge: what it brings is another module's,
and `std/traits` reopening `Int64` expects to find the tower `std/int`
wrote. A `require` names a file rather than a module, relative to the
file that wrote it, and what it brings is read as if it had been written
there: `src/iyi/prelude.iyi` is fourteen files and one program.

The distinction is load-bearing beyond resolution. A struct is given the
`initialize` that `new` calls when it declares none, and the compiler
writes that once, where the struct was declared. For an import that is
the other module: `src/std/named_tuple.iyi` reopens a `NamedTuple` that
`src/std/tuple.iyi` owns, and only `tuple.iyi` reports the `initialize`.
For a require it is this program's own text, so `prelude.iyi` reopening
the `Pointer` that `primitives.iyi` declared reports it. All three were
measured before the rule was written.

A macro runs where its declaration reaches the file, which is the same
edge again. `getter` and `property` are declared in `src/iyi/macros.iyi`,
so a module file writing `getter a : Int32` declares no reader at all,
and the compiler agrees: it reports the type with `initialize` and
nothing else. `prelude.iyi` requires that file, so its `property
next_node : IyiDeferNode?` writes the reader, the writer and the field.
The expander answers what such an argument is, with
`name.is_a?(TypeDeclaration)`, and the two halves of it, with `name.var`
and `name.type`.

A `lib` is a type the compiler prints as `libtype` and the functions it
declares are its methods. There is no body to walk, so the parser keeps
the names while it skips to the end.

Measured after all of it: the standard library **35 agree, 0 differ**,
the prelude **15 agree, 0 differ**, the samples **23 agree, 0 differ**.
Every file with an oracle agrees with it. The expansion is load-bearing:
making `expand_calls` return its source unchanged turns `prelude.iyi`
from `agree` into a file missing exactly `next_node` and `next_node=`,
and restoring it byte-for-byte turns it back.

## The inference slice

`semantic/infer.iyi` infers the return type of every called internal method
in `semantic/fixtures/infer.iyi`. The oracle runs `Program#semantic` and
reads the typed `DefInstance` objects the current compiler created:

    bash selfhost/semantic/infer_diff.sh
    agree: <Program>#integer=Int32 <Program>#maybe=(Int32 | Nil) <Program>#text=String <Program>#truth=Bool

This slice is call-driven rather than another declaration walk. The fixture
contains an uncalled method and neither side reports it. The iyi pass carries
literal types, typed parameters, local assignment and lookup, expression-list
results, and branch unions. Its gate is load-bearing: changing the inferred
integer type to `Int64` changes two answers and exits non-zero; restoring the
source byte-for-byte returns the exact four rows above.

The second fixture, `fixtures/infer_calls.iyi`, carries what a body does
rather than what it holds, and `infer_diff.sh` now runs every fixture,
because a slice that grew a second one and kept checking the first proves
only the first:

    infer.iyi agrees: <Program>#integer=Int32 <Program>#maybe=(Int32 | Nil) <Program>#text=String <Program>#truth=Bool
    infer_calls.iyi agrees: <Program>#character=Char <Program>#early=(Int32 | String) <Program>#fraction=Float64 <Program>#leaf=Int32 <Program>#loops=Nil <Program>#reaches_leaf=Int32 <Program>#recursive=Int32

Five things the first fixture did not say:

* A call to a method in the same file is typed by that method, which is
  the first answer reading one method cannot give.
* A method that reaches itself is typed by the way out that does not.
  The recursive call answers nothing, and nothing is what a union with it
  drops.
* A body has more than one way out. `early` returns a `String` and ends
  on an `Int32`, and the answer is both. A body that ends in a `return`
  is worth nothing on its own, which is how `recursive` answers `Int32`
  rather than `(Nil | Int32)`.
* A loop is not a value.
* `1.5` is a `Float64` and `'c'` is a `Char`. A literal's suffix is not
  here: the lexer drops it, so `1_i64` arrives as `1`, and neither
  fixture writes one.

The second gate is load-bearing too: dropping the collection of `return`
types changes two rows and exits non-zero, and restoring the file
byte-for-byte returns the rows above.

### A method on a value

The third fixture, `fixtures/infer_types.iyi`, is the first one with a
type in it, and it is where inference stops being a walk over one file's
top level:

    infer_types.iyi agrees: <Program>#make_label=Label <Program>#make_point=Point <Program>#reach_field=Int32 <Program>#reach_self=Int32 Label#initialize=String Label.class#new=Label Point#first=Int32 Point#initialize=Int32 Point#x=Int32 Point#y=Int32 Point.class#new=Point

Eleven rows, and each one is a different question:

* A constructor is worth the type it builds, and it reaches the
  `initialize` that the `new` the compiler writes calls. That `new`
  lives on the metaclass, which is why it prints as `Point.class#new`.
* `initialize` needs no special case. The parser writes
  `def initialize(@x : Int32, @y : Int32)` as two arguments and two
  assignments, so it is typed by its body like anything else, and the
  body ends on `@y = y`: `Point#initialize` is an `Int32` and `Label`'s
  is a `String`.
* A field's type is read off that same constructor. Reading it means
  inferring a body, and that is not a call, so it is done with recording
  turned off: a field read must not make `initialize` look reached.
* A call on a local is looked up on the local's type. `point` carries
  what `make_point` answered.
* A call written with no receiver inside a method is a call on that
  method's own type before it is one on the program. `Point#first` calls
  `x`, and `x` is `Point`'s.
* Nothing calls `Point#unused` or `Label#text`, and neither side reports
  them. `Point#x` is reported because `first` reaches it, not because it
  is declared.

No fixture calls a method the prelude owns. The pass runs on one file
with no prelude, so `i < 3` is an undefined method rather than a
comparison, and the first attempt at the second fixture died on exactly
that. Typing `1 + 1` means loading the prelude, which is the work the
bootstrap needs.

This gate is load-bearing as well: making the receiver lookup refuse the
types it knows turns `reach_field` and `reach_self` into `Unknown` and
exits non-zero, while the two fixtures with no receiver in them keep
agreeing. Restoring the file byte-for-byte returns the rows above.

### A method the prelude owns

The wall the first three fixtures named was `1 + 1`. They ran on one
file with nothing under it, so there was no `+` to reach, and the
fixture that tried died on exactly that. `fixtures/infer_prelude.iyi`
requires the prelude, which is what the bootstrap does:

    infer_prelude.iyi agrees: <Program>#fraction=Float64 <Program>#length=Int32 <Program>#sum=Int32 <Program>#through_local=Int32 <Program>#wider=Int64

R-2 is what makes this tractable rather than a second compiler. An
exported method carries its return type, so a required method is typed
by reading its declaration rather than by inferring its body:
`def to_i64 : Int64` answers an `Int64`, and `def +(other : Int32) :
self` answers whatever the receiver is. Nothing in the prelude is
inferred and nothing in it is reported: a row is this file's method or
it is nothing.

Two things had to be true for `1 + 1` to answer `Int32`.

The prelude writes its integer tower with a macro. `to_i64` and `+` are
not written anywhere in `src/iyi`: they are a `{% for %}` over a map and
a cross of operators in `src/iyi/primitives.iyi`, so the pass expands
each required file before reading it. Reading the source instead finds
no method of that name at all, which is what the mutation proof shows.

And `self` in a type position is its own node rather than a path.
Reading the return type as a path answered nothing, so every operator
the prelude declares that way came out `Unknown` while `to_i64` was
already right. A call with an argument also has to choose among
overloads, and it chooses by the type of the first argument: `1 + 1` and
`1 + 1.5` are one name and two answers.

Writing this slice found a defect in the expander rather than in the
prelude. `macro_params` asked a string for its last bracket with
`rindex`, which is a method `std/text` adds, and `selfhost/macro/expand`
imports nothing. It compiled anyway, because the declaration pass that
uses it does import `std/text`, and the macro driver on its own stopped
building. A module that leans on what another file imported is not a
module.

This gate is load-bearing: reading the required files without expanding
them turns `sum`, `fraction` and `wider` into `Unknown` and exits
non-zero, while the three fixtures with no prelude under them keep
agreeing.

## The lexer, on everything

    bash selfhost/lexer/diff.sh              # 27 samples
    bash selfhost/lexer/diff.sh src/std/*.iyi  # 65 of the standard library
    bash selfhost/lexer/where.sh <file>      # the first token that differs

Measured: **116 files agree, 0 differ**, from 6 when the corpus skipped
every file with a `#{` in it. Four files have no oracle at all, which is
reported rather than skipped.

The skip was the point. Twenty-one files were out of scope for
interpolation, and eleven of them turned out to differ for reasons that
had nothing to do with it: `**`, `//`, `@[`, `{%`, `{{`, `%w(`, symbols,
a line continuation, a byte-order mark. Nothing was wrong with the
measurement while those files sat outside it, and nothing was right
either.

What interpolation needed is a lexer that holds what it is in the middle
of. A string body is not code and an interpolation inside one is, so the
two alternate and they nest: `"to_a #{n.to_a.join(",")}"` is a string
holding code holding a string. The port keeps a stack of modes and the
oracle keeps the same stack, because the current lexer only reads a body
when a parser tells it to.

Three of the differences were in the instrument:

- After `INTERPOLATION_START` the driver kept asking for string tokens,
  so `#{name}!` read as the string `name}!`. An interpolation is code.
- A string written inside an interpolation ends back into that
  interpolation, not into the string around it. Popping the wrong
  context made the quote after it open a second string that ran to the
  end of the file.
- A stream that stops where the lexer raised is not an oracle. The
  prelude reaches a `{%` the lexer wants a parser's macro state for, and
  the tokens before it looked like agreement followed by a difference
  that was ours. The oracle now prints nothing unless it reaches the
  end, and `diff.sh` reports the file as having none.

Two rules were measured rather than assumed. A number is reported as
what it means: `0x80` is `128`, `0xFFFFFFFFFFFFFFFF_u64` is
`18446744073709551615`, and `1_000` is `1000`, while `1e3` stays as it
was written. And `empty?`, `nil?` and `in?` are one word where `to_u64!`
and `end!` are two, so a question mark is part of a name here and a bang
is not.

The gate is load-bearing: making the interpolation branch match a
character that never appears turns the sample corpus from 27 agreeing
into 6, and restoring the file byte-for-byte turns it back.
