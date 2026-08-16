# iyi

**A fork of [Crystal](https://crystal-lang.org) that answers one question: what
does a language look like if separate compilation is a rule rather than a
feature?**

Crystal's syntax, union types, nil-safety and blocks are kept as they are. What
changes is the compilation model — and everything that model forces. The design
is in [SPEC.md](SPEC.md), which is a working document rather than a manual: it
records what was measured, what was tried and abandoned, and why.

This is `0.1.0` in the sense of "the first thing that proves the claim", not in
the sense of "ready for your project". Read the limits before the numbers.

## The program that makes the argument

A web framework's DSL — the Sinatra feel — except that the library exports
names and the *program* decides which ones it wants unqualified. Nothing is
injected into anybody's namespace:

```crystal
module samples/webapp

import kemal/dsl
import kemal/router

using kemal/dsl                        # `get`, `post`, `mount` — because this file said so
using kemal/router::{Router, Context}

get "/" do |env|
  "home"
end

get "/count" do |env|
  42                                   # anything implementing IntoBody, not just String
end

users = Router.new
users.namespace "/admin" do |admin|
  admin.get "/dashboard" do |env|
    "dashboard"
  end
end

mount "/v1", users
```

That is [`samples/iyi/webapp.iyi`](samples/iyi/webapp.iyi), a port of
[Kemal](https://kemalcr.com)'s router, and it runs. Now add a route that returns
something a body cannot be made of:

```crystal
get "/bad" do |env|
  [1, 2, 3]
end
```

```console
$ iyi build samples/iyi/webapp.iyi
In webapp.iyi:33:1

 33 | get "/bad" do |env|
      ^--
Error: Array(Int32) does not implement Kemal::Router::IntoBody, required by `B` in `get`
```

**Kemal cannot say this.** `HTTP::Server::Context -> _` accepts the block and
returns an empty body at runtime, forever, on every request. Here the handler's
return type is a type parameter bounded by a trait, so the framework's promise
— "give me something I can turn into a body" — is a thing the compiler checks
at the line where the mistake is, in a module that has never heard of your
types.

And the same program builds when the framework's source is not on the machine:

```console
$ iyi build --emit-iyimod mods samples/iyi/webapp.iyi   # writes kemal/router.iyimod, ...
$ rm -rf samples/iyi/kemal                              # the library's source, gone
$ iyi build --use-iyimod mods samples/iyi/webapp.iyi    # builds, links, runs, same output
```

## The rules the rest follows from

| Rule | |
|---|---|
| **R-1** | A module is the unit of compilation. `import` forms a DAG. Compiling a module reads its dependencies' **declarations**, never their bodies. |
| **R-2** | Everything a module exports (`pub`) writes down full parameter and return types. Unexported code infers as usual. |
| **R-2b** | `using` brings exported names into unqualified scope — written by the consumer, not by the library. |
| **R-3** | No open classes. `impl Trait for Type` lives in the module that declares the trait or the type. |

R-1 is what a `.iyimod` is: a module's declarations, the bodies a consumer has
to compile for itself, and its machine code, in one file. R-3 is what makes a
consumer able to answer "does this type implement that trait?" without reading
anything else.

## Getting it

```console
$ tar -xzf iyi-0.1.0-dev-linux-x86_64.tar.gz -C ~/.local
$ ~/.local/bin/iyi run ~/.local/share/iyi/samples/hello.iyi
```

The tarball is relocatable: `bin/iyi` finds its prelude — 56 KB of it — beside
itself, so there is nothing to configure and no `CRYSTAL_PATH` to set. What it
needs on the machine is a C toolchain (`cc`, which iyi asks once for the link
command and then bypasses) and **libgc**, which every program it produces links
against: `apt install libgc-dev` or your system's equivalent.

Building it instead needs LLVM 19 and a Crystal compiler to bootstrap:

```console
$ make iyi                # .build/iyi
$ make iyi-tarball        # .build/iyi-0.1.0-dev-<os>-<arch>.tar.gz
$ sudo make install_iyi   # PREFIX=/usr/local by default
```

`make crystal` builds the same compiler under its Crystal name, which is what
the specs and the bench use.

## More of the language

**Traits, and impls for a generic type.** There is no inheritance to reopen and
no monkey patching to lose track of: a type gets behaviour from an `impl`, and
that `impl` lives with the trait or with the type (R-3).

```crystal
pub trait Show
  abstract def show : String
end

pub struct Box(T)
  getter value : T

  def initialize(@value : T)
  end
end

impl Show for Box(T) forall T          # `forall` introduces T, and is required
  def show : String
    "Box(#{value})"
  end
end

puts Box.new(41).show                  # => Box(41)
puts Box.new("hi").show                # => Box(hi)
```

The `forall` is not ceremony. Without it, whether `T` names a new parameter or a
type that happens to be in scope would depend on what a file imports — so adding
an export to a library could change what somebody's `impl` means.

**One `each`, fifty-seven methods.** `samples/iyi/std/enumerable.iyi` is
`Enumerable` ported to a trait: one requirement and 57 defaults. Implement the
requirement, answer the associated type, and the rest arrives — for any element
type, checked once at the `impl` rather than at every call.

```crystal
pub struct Nums
  def initialize(@a : Array(Int32))
  end
end

impl Enumerable for Nums
  type Elem = Int32                    # the associated type, answered by the impl
  def each(& : Int32 -> Nil) : Nil
    @a.each { |x| yield x }
  end
end

n = Nums.new([3, 1, 4, 1, 5])
puts n.to_a.join(",")                  # => 3,1,4,1,5
puts n.map { |x| x * 2 }.join(",")     # => 6,2,8,2,10
puts n.sorted.join(",")                # => 1,1,3,4,5
puts n.first                           # => 3
```

**Errors are ordinary union members.** No `Result`, no exception hierarchy, no
new machinery: a union already carries a type id, and what makes a member an
*error* member is that its type implements `Error`.

```crystal
pub def load(path : String) : Int32 | IOError | ParseError
  text = read(path)!                   # `!` returns the error member from here,
  to_number(text)!                     # or narrows to the value and carries on
end

case load(path)
in Int32      then puts "read #{it}"
in IOError    then puts "io:    #{it.message}"
in ParseError then puts "parse: #{it.message}"
end
```

Adding an error to `load`'s return type is a change every caller is told about,
because an incomplete `case` does not compile. Delete the `ParseError` branch
from the sample and the compiler names what is missing:

```console
$ iyi build samples/iyi/errors.iyi
In errors.iyi:64:3

 64 | case load(path)
      ^
Error: case is not exhaustive.

Missing types:
 - Samples::Errors::ParseError
```

## The samples

```console
$ iyi run samples/iyi/hello.iyi
Hello, iyi!
HELLO, IYI!
BEEP 42
Hello, crystal!
BEEP 7
-> BEEP 9
```

Eight programs live in [`samples/iyi`](samples/iyi), and each is documentation
for a part of the design rather than a demo: `hello` (traits and `impl`),
`modules` (`import` and `using` across files), `generics`, `errors`,
`collections` (the trait above, implemented twice for different element types),
`immutable` (a shareable collection, and the copy that makes it safe),
`init_order` (initialisation order across a module graph) and `webapp`.

**Compiling against declarations rather than source** is checked rather than
claimed. `bash bench/samples_roundtrip.sh` builds the five samples that import
anything, deletes every imported module's source, builds again from the
artifacts and compares what the two programs print;
`spec/compiler/iyimod_spec.cr` checks the same property on programs written for
it. An artifact is readable, too:

```console
$ iyi mod dump mods/kemal/router.iyimod | head -20
module        kemal/router
compiler      1.22.0-dev+cb85d653a
...
exports
  pub struct Context
    @method : String
    @path : String
    def initialize(method : String, path : String)
```

## What it costs, measured

`python3 bench/build_speed.py` produces the table below rather than this file
quoting one. On one Linux machine, release compiler, warm builds:

| program | iyi | `go build` |
|---|---|---|
| `hello` (5 lines) | **0.07 s** | 0.10 s |
| generated pair, 6,900 lines | 0.23 s | **0.09 s** |

Both halves of the second pair are generated from one loop
(`bench/build_speed/generate_pair.py`) and the bench refuses to time them unless
the two binaries print the same thing. **Read the second row before quoting the
first**: iyi wins where fixed costs are the whole bill and loses once there is a
program, at roughly 25 ms per thousand lines against a Go build that barely
moves. The front end alone is 0.024 s on `hello`, against a 0.050 s target.

## What is not here

- **No IO beyond `puts`.** The prelude is 1,053 lines on purpose: integers,
  booleans, a string, one sequence, one dictionary. No files, no sockets, no
  formatting.
- **No concurrency.** III.4 of SPEC.md specifies structured concurrency,
  scope-owned cancellation and a `Share` marker; none of it is built.
- **No package manager, no standard library, no self-hosting.**
- **Linux x86-64 only.** Other targets are Crystal's and untested here.
- **Artifacts are version-locked.** A `.iyimod` from another compiler build is
  rejected and rebuilt, never migrated.
- **`derive` macros do not cross modules yet**, though a module's own macros
  travel with its artifact.

## Where things are

| | |
|---|---|
| [SPEC.md](SPEC.md) | the design, and the record of what measurement settled |
| [`samples/iyi`](samples/iyi) | eight programs, each documenting a part of it |
| [`src/iyi`](src/iyi) | the prelude, 1,053 lines |
| [`src/compiler/crystal/iyimod.cr`](src/compiler/crystal/iyimod.cr) | the artifact format |
| [`bench/build_speed.py`](bench/build_speed.py) | the numbers above, and the gate that fails until they hold |
| [README.crystal.md](README.crystal.md) | Crystal's own README, kept |

## Licence and provenance

iyi is a fork of the Crystal compiler and carries Crystal's licence and
copyright: Apache 2.0, Copyright 2012-2026 Manas Technology Solutions. See
[LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). Everything here that is not
Crystal's is a change to Crystal's source, and the compiler still identifies
itself as `Crystal 1.22.0-dev` because it is one.
