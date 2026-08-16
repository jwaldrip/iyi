# Contributing

This is a fork of [Crystal](https://github.com/crystal-lang/crystal), and it is
pre-release. If your issue is with Crystal the language, it belongs in Crystal's
tracker, not here; what belongs here is anything about the rules in
[SPEC.md](SPEC.md), the `.iyimod` artifact, or the compiler's behaviour on a
`.iyi` file.

## Building it

You need LLVM 19, a Crystal compiler to bootstrap from, and libgc.

```console
$ make crystal            # the compiler, as .build/crystal
$ make iyi                # the same compiler under its own name
```

`bin/crystal` runs the built compiler with this checkout's sources on its path,
which is what every command below assumes.

## What has to pass

One workflow, `.github/workflows/iyi.yml`, and it is the whole of CI:

```console
$ ./bin/crystal tool format --check src spec
$ ./bin/crystal spec spec/compiler/iyimod_spec.cr spec/compiler/iyi_import_spec.cr \
    spec/compiler/semantic/iyi_spec.cr spec/compiler/compiler_spec.cr
$ make compiler_spec primitives_spec std_spec
$ bash bench/samples_roundtrip.sh
```

The last one is the claim taken literally: it builds the samples, deletes the
imported modules' source, builds them again from the artifacts, and compares
what the two programs print.

## What this repository expects of a change

**A number, where the change is about speed.** `bench/build_speed.py` prints the
table and exits non-zero while the front-end target is unmet. SPEC.md records
what was measured and what was thrown away for the reason it records; a claim
without a measurement does not go in it.

**A sample or a spec, where the change is about the language.** The eight
programs in `samples/iyi` are each there to document one part of the design, and
they run in CI.

**Crystal's licence and copyright stay.** Everything here is a change to
Crystal's source: Apache 2.0, Copyright 2012-2026 Manas Technology Solutions.
See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
