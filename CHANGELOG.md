# Changelog

## Unreleased

Master is `0.2.0-dev`, and under the rule below that means every build of it
interoperates with nothing but itself. That is the point: a version between two
releases names no compiler.

### Changed

- **An artifact is read by the release that wrote it, not by the build.** A
  `.iyimod` was locked to the exact compiler build, commit and all, so two
  builds of the same version refused each other's modules and handing one to
  somebody meant handing them your compiler too. The identity is now the
  released version, the target and the flags: every build of iyi 0.1.0 reads
  every other build's artifacts on the same target under the same flags. A
  `-dev` version keeps the commit, because it names no release. The version
  comes from `src/IYI_VERSION`, which is also what the binary reports and what
  the tarball is named after.

### Added

- **`pub macro`, so a macro can cross a module boundary.** Every macro a module
  writes already travelled in its artifact, because a body that travels may
  call one, but none of them was reachable: `pub` did not take a macro. A
  marked one is now reachable exactly as a `pub def` is, unqualified after
  `using` or through the module's name, and it works against an artifact with
  the module's source deleted. What it exports is a name and an arity, because
  a macro takes syntax and returns syntax.

  Two things worth knowing. Closing this found the hole under it: a macro's
  visibility was never set, so **every** module's macros were already callable
  through its name — that is refused now, with the sentence an unexported `def`
  gets. And macros are not hygienic, so a `pub macro` that writes `tmp = 99`
  assigns to the consumer's `tmp`; SPEC.md IV.4 says so in full.

- **`iyi tool format` formats iyi.** The formatter is Crystal's and knew none
  of iyi's syntax, so a module header, a `pub`, a `trait`, an `impl`, a
  `using`, a bounded `forall`, a `where`, a `defer`, a `!` or an `.or` sent it
  into "there's a bug formatting this file". It knows all of them now, and a
  directory is searched for `.iyi` files as well as `.cr` ones. The prelude and
  the nine samples format to themselves, which is the test that made the last
  three of those show up.

### Fixed

- **A generic imported from an artifact links again when its type argument is
  inferred.** `Box(Int32).new(42)` always worked and `Box.new(42)` did not.
  Inference makes `new` a method on `Box(T)`, which is the artifact's own type,
  and the rule that says "this type's machine code is in the artifact" was
  reading the generic itself. An artifact carries a unit for every non-generic
  type a module declares and none for a generic one, because a generic has
  machine code only once somebody picks its arguments, and the consumer is who
  picks them. So the consumer declared a `new` that nothing defined and the
  program failed to link, saying `undefined reference to Box(T)::new<Int32>`.
  The consumer's rule now matches the producer's. Reported after 0.1.0 went
  out.

## 0.1.0 — 2026-08-18

The first release. There is nothing to compare it against, so this says what is
in it rather than what changed, and what a later version will have to keep
faith with.

### The language

Four rules, and everything else follows from them (SPEC.md):

- **R-1** A module is the unit of compilation. `import` forms a DAG, and
  compiling a module reads its imports' declarations, never their bodies.
- **R-2** Everything a module exports (`pub`) writes down full parameter and
  return types.
- **R-2b** `using` brings exported names into unqualified scope, written by the
  consumer.
- **R-3** No open classes. `impl Trait for Type` lives in the module that
  declares the trait or the one that declares the type.

Traits with defaults and associated types, generic impls with `forall`, errors
as ordinary union members with `!` propagation, `defer` scoped to the block,
and Crystal's syntax otherwise: union types, nil-safety, blocks, local
inference, macros.

### The artifact

`.iyimod` **format v19**. A module's declarations, its macros, the bodies that
have to travel, its object code, and a checksum per section. Artifacts are
version-locked: one written by another build of the compiler is refused and
rebuilt, never migrated, so a later version bumping this number is expected
rather than a breakage.

`iyi build --emit-iyimod DIR` writes them, `--use-iyimod DIR` builds against
them, and `iyi mod dump` prints one as text.

### The tool

`iyi` takes `build`, `run`, `mod`, `env`, `clear_cache`, `tool`, `version` and
`help`. `crystal` is the same compiler under its own name, and it still
compiles `.cr` files. `eval` is deliberately not on iyi's list: it has no
filename, so it gets Crystal's prelude and Crystal's rules, and a command that
answers in another language is worse than one that says where it went.

### Measured

One machine, release compiler, best of seven, seconds. A 30-module,
7,208-line project, rebuilt after changing one line in one module:

| | iyi | Crystal | `go build` |
|---|---|---|---|
| rebuild after one edit | **0.13** | 1.17 | 0.16 |

The same edit with every module read from source instead of from artifacts
costs 0.23 s, which is what R-1 is worth on this project. A full build of a
6,900-line program from scratch is 0.24 s against `go build`'s 0.09 s, which is
where iyi loses. `python3 bench/incremental.py` and `python3
bench/build_speed.py` print both, and refuse to time programs that do not agree
on their output.

### Not in this release

No IO beyond `puts`. No concurrency: SPEC.md III.4 specifies it and none of it
is built. No package manager, no standard library, no self-hosting. Linux
x86-64 only. `derive` macros do not cross modules. The prelude is 1,184 lines
and its collections are small, and `a[-1]` raises rather than indexing from the
end. The formatter is Crystal's and does not know iyi's syntax: `iyi tool
format` says so and leaves `.iyi` files alone.

### Provenance

A fork of [Crystal](https://github.com/crystal-lang/crystal) at 1.22.0-dev,
Apache 2.0 with Swift exception, Copyright 2012-2026 Manas Technology
Solutions. The backend, the GC and the type checker are Crystal's work. The
compiler reports itself as `Crystal 1.22.0-dev` because that is what it is, and
it is bootstrapped by released Crystal 1.21.0, which is the version CI pins
and the one to install if you are building this from source.

Two bugs in Crystal's own compiler were found here and fixed in this fork; they
belong upstream and are separate commits for that reason:

- `Crystal.relative_filename` chopped the working directory off any path that
  merely began with its name, so a build in `/x/crystal` with a cache in
  `/x/crystal-cache` wrote its object files to `-cache/…`.
- The cache cleaner deleted the directory of a build that was still running,
  because it keeps the ten most recently modified directories and a build stops
  looking recent while its units sit in an optimization pass.
