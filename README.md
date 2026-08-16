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

## What works today

```console
$ ./bin/crystal run samples/iyi/hello.iyi   # or: iyi run samples/iyi/hello.iyi
Hello, iyi!
HELLO, IYI!
BEEP 42
Hello, crystal!
BEEP 7
-> BEEP 9
```

Eight sample programs live in [`samples/iyi`](samples/iyi) and each one is
documentation for a part of the design: `hello` (traits and `impl`), `modules`
(`import` and `using`), `generics`, `errors`, `collections` (a trait ported from
`Enumerable`, implemented twice), `immutable`, `init_order` (initialisation
order across a module graph) and `webapp` — a port of the [Kemal](https://kemalcr.com)
router, which is the one program here that looks like real code.

**Separate compilation, from the command line:**

```console
$ iyi build --emit-iyimod mods samples/iyi/webapp.iyi   # writes mods/kemal/router.iyimod, ...
$ iyi mod dump mods/kemal/router.iyimod                 # reads one back, as text
$ rm -rf samples/iyi/kemal                              # delete the library's source
$ iyi build --use-iyimod mods samples/iyi/webapp.iyi    # still builds, links and runs
```

That last step is the whole point: the consumer never opens the module's source,
and the program it produces prints what the build from source prints.
`bash bench/samples_roundtrip.sh` does it for the five samples that import
anything — deleting each module's source before the second build, because that
deletion is the only way to be sure — and `spec/compiler/iyimod_spec.cr` checks
the same property on programs written for it.

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
