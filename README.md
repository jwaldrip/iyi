# iyi

**A fork of [Crystal](https://crystal-lang.org) built to answer one question:
what does a language look like when separate compilation is a rule instead of a
feature?**

The syntax stays. Union types, nil-safety, blocks, local inference: all kept.
What changes is the compilation model, and everything that model forces.

The design lives in [SPEC.md](SPEC.md). It is a working document, not a manual.
It records what was measured, what was tried and thrown away, and why.

This is `0.1.0` in the sense of "the first thing that proves the claim". It is
not ready for your project: no IO beyond `puts`, no concurrency, no package
manager, Linux x86-64 only. [What is not here](#what-is-not-here) says the rest,
and it is worth reading before the numbers are.

## The program that makes the argument

A web framework's DSL, with the Sinatra feel intact. The library exports names.
The program picks which ones it wants unqualified. Nothing gets injected into
anybody's namespace.

```crystal
module samples/webapp

import kemal/dsl
import kemal/router

using kemal/dsl                        # get, post, mount: because this file asked
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

That file is [`samples/iyi/webapp.iyi`](samples/iyi/webapp.iyi), a port of
[Kemal](https://kemalcr.com)'s router, and it runs. Now add a route whose
handler returns something a body cannot be made of:

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

**Kemal cannot say this.** It accepts the same block and serves an empty body,
on every request, forever. Here the handler's return type is a type parameter
bounded by a trait. The framework's promise, "give me something I can turn into
a body", is checked at the line where the mistake is, by a module that has never
heard of your types.

The same program also builds when the framework's source is not on the machine:

```console
$ iyi build --emit-iyimod mods samples/iyi/webapp.iyi   # writes kemal/router.iyimod, ...
$ rm -rf samples/iyi/kemal                              # the library's source, gone
$ iyi build --use-iyimod mods samples/iyi/webapp.iyi    # builds, links, runs, same output
```

## What it costs, measured

**The loop a person is actually in.** Nobody uses a language through full
builds; they use it through changing a line and building again. Thirty
modules, 300 types, 7,208 lines, written in both languages by one generator
and refused unless the two binaries print the same number before anything is
timed. Best of 7 on one idle Linux machine, release compiler, seconds:

| what changed | iyi | `go build` |
|---|---|---|
| **one module's body** | **0.17** | 0.20 |
| the entry file only | **0.15** | 0.21 |
| nothing at all | 0.15 | 0.09 |
| nothing cached anywhere | 0.74 | 3.89 |
| the same edit, *without* artifacts | 0.29 | — |

**That last row is R-1's whole argument with a price on it.** Build the same
edit with all thirty modules read from source and it costs 0.29 s; with the
`.iyimod` files in hand the other twenty-nine arrive as declarations instead
of source and it costs 0.17 s. The rule pays 1.7x on the loop it was written
for, and it pays more as the code you are *not* editing grows.

**Go is the column to stand next to because Go is good at this.** Being 15%
ahead of it is not the headline; being in the same class is. The last row is
what the same edit costs with the rule switched off, and a compiler without it
pays that on every build there will ever be. Run it yourself with
`python3 bench/incremental.py`.

**Now the less flattering number, and it is a full build.** `python3
bench/build_speed.py`, same machine, warm:

| program | iyi | `go build` |
|---|---|---|
| `hello` (5 lines) | **0.06 s** | 0.08 s |
| generated pair, 6,900 lines | 0.22 s | **0.08 s** |

**Read that second row before quoting the first.** iyi wins where fixed costs
are the whole bill and loses once there is a program to compile from scratch,
at roughly 25 ms per thousand lines. Both halves of the pair come out of one
generator, and the bench refuses to time them unless the two binaries print
the same thing. The front end on its own is 0.034 s for `hello` against a
target of 0.050 s, and 0.018 s of that is the compiler process starting up
before it reads anything.

## The rules everything follows from

| Rule | |
|---|---|
| **R-1** | A module is the unit of compilation. `import` forms a DAG. Compiling a module reads its dependencies' **declarations**, never their bodies. |
| **R-2** | Everything a module exports (`pub`) writes down full parameter and return types. Unexported code infers as usual. |
| **R-2b** | `using` brings exported names into unqualified scope. The consumer writes it, not the library. |
| **R-3** | No open classes. `impl Trait for Type` lives in the module that declares the trait or the type. |

R-1 is what a `.iyimod` file is: a module's declarations, the bodies a consumer
has to compile for itself, and its machine code, in one file. R-3 is what lets a
consumer answer "does this type implement that trait?" without reading anything
else.

## Getting it

```console
$ tar -xzf iyi-0.1.0-dev-linux-x86_64.tar.gz -C ~/.local
$ ~/.local/bin/iyi run ~/.local/share/iyi/samples/hello.iyi
```

The tarball is relocatable. `bin/iyi` finds its prelude beside itself, all 56 KB
of it, so there is nothing to configure and no `CRYSTAL_PATH` to set.

Two things have to be on the machine. A C toolchain, because the link goes
through one. And **libgc**, which every program iyi produces links against:
`apt install libgc-dev`, or your system's equivalent.

Building it instead needs LLVM 19 and a Crystal compiler to bootstrap from:

```console
$ make iyi                # .build/iyi
$ make iyi-tarball        # .build/iyi-0.1.0-dev-<os>-<arch>.tar.gz
$ sudo make install_iyi   # PREFIX=/usr/local by default
```

What a release build is, in one line, since the version belongs to the binary
and the tarball alike:

```console
$ make iyi iyi-tarball release=1 IYI_VERSION=0.1.0
```

`make crystal` builds the same compiler under its Crystal name. That is the one
the specs and the bench use.

## More of the language

**Traits, and impls for a generic type.** Nothing to reopen, nothing to monkey
patch. A type gets behaviour from an `impl`, and that `impl` lives with the
trait or with the type.

```crystal
pub trait Show
  abstract def show : String
end

pub struct Box(T)
  getter value : T

  def initialize(@value : T)
  end
end

impl Show for Box(T) forall T          # forall introduces T, and is required
  def show : String
    "Box(#{value})"
  end
end

puts Box.new(41).show                  # => Box(41)
puts Box.new("hi").show                # => Box(hi)
```

The `forall` is not ceremony. Drop it and whether `T` names a new parameter or a
type already in scope would depend on what the file imports. A library could
then change the meaning of your `impl` by adding an export.

**One `each`, fifty-seven methods.** `samples/iyi/std/enumerable.iyi` is
`Enumerable` ported to a trait: one requirement, 57 defaults. Implement the
requirement, answer the associated type, and the rest arrives. It is checked
once at the `impl`, not at every call.

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

**Errors are ordinary union members.** No `Result` wrapper, no exception
hierarchy, no new machinery. A union already carries a type id. What makes a
member an *error* member is that its type implements `Error`.

```crystal
pub def load(path : String) : Int32 | IOError | ParseError
  text = read(path)!                   # ! returns the error member from here,
  to_number(text)!                     # or narrows to the value and carries on
end

case load(path)
in Int32      then puts "read #{it}"
in IOError    then puts "io:    #{it.message}"
in ParseError then puts "parse: #{it.message}"
end
```

Add an error to `load`'s return type and every caller hears about it, because an
incomplete `case` does not compile. Delete the `ParseError` branch from the
sample and the compiler names what is missing:

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

Eight programs live in [`samples/iyi`](samples/iyi). Each one documents a part
of the design rather than showing off: `hello` (traits and `impl`), `modules`
(`import` and `using` across files), `generics`, `errors`, `collections` (the
trait above, implemented twice for different element types), `immutable` (a
shareable collection, and the copy that makes it safe), `init_order`
(initialisation order across a module graph), and `webapp`.

Compiling against declarations instead of source is checked, not asserted.
`bash bench/samples_roundtrip.sh` builds the five samples that import anything,
deletes every imported module's source, builds again from the artifacts, and
compares what the two programs print. `spec/compiler/iyimod_spec.cr` checks the
same property on programs written for it.

Artifacts are readable:

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

## What is not here

- **No IO beyond `puts`.** The prelude is 1,053 lines on purpose: integers,
  booleans, a string, one sequence, one dictionary. No files, no sockets, no
  formatting.
- **No concurrency.** SPEC.md III.4 specifies structured concurrency,
  scope-owned cancellation and a `Share` marker. None of it is built.
- **No package manager, no standard library, no self-hosting.**
- **Linux x86-64 only.** Other targets belong to Crystal and are untested here.
- **Artifacts are version-locked.** A `.iyimod` written by another build of the
  compiler is rejected and rebuilt, never migrated.
- **`derive` macros do not cross modules yet.** A module's own macros do travel
  with its artifact.

## Where things are

| | |
|---|---|
| [SPEC.md](SPEC.md) | the design, and the record of what measurement settled |
| [`samples/iyi`](samples/iyi) | eight programs, each documenting a part of it |
| [`src/iyi`](src/iyi) | the prelude, 1,053 lines |
| [`src/compiler/crystal/iyimod.cr`](src/compiler/crystal/iyimod.cr) | the artifact format |
| [`bench/incremental.py`](bench/incremental.py) | the edit loop, against Go, generated in both languages |
| [`bench/build_speed.py`](bench/build_speed.py) | the full builds, and the gate that fails until the target holds |
| [README.crystal.md](README.crystal.md) | Crystal's own README, kept |

## Licence and provenance

iyi is a fork of the Crystal compiler and carries Crystal's licence and
copyright: Apache 2.0, Copyright 2012-2026 Manas Technology Solutions. See
[LICENSE](LICENSE) and [NOTICE.md](NOTICE.md). Everything here that is not
Crystal's is a change to Crystal's source, and the compiler still reports itself
as `Crystal 1.22.0-dev`, because that is what it is.
