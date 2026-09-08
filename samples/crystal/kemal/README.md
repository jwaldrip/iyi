# A kemal application, in iyi

[`app.iyi`](app.iyi) is a kemal application: routes, URL and query parameters,
a JSON endpoint that reads a POST body, and a 404 handler. The shard is not
vendored — `shard.yml` pins kemal 1.12.0 and `shards install` fetches it, the
same as any Crystal project.

It builds two ways, and the point of the sample is that both answer the same.

The commands below are written from a checkout. This sample ships in the
tarball too, and both halves work there: `iyi bind` runs the boundary's two
steps as the `iyi` binary, against the Crystal library the tarball carries.

## From source

kemal is compiled beside the program, which is what `--crystal` means: iyi's
own library is swapped for Crystal's, and a `require` reads the shard's source.

```sh
cd samples/crystal/kemal
shards install

# Absolute, because the fill build below runs with `mods` as its working
# directory and a relative path would resolve under it.
REPO="$(cd ../../.. && pwd)"
export CRYSTAL_PATH="$PWD/lib:$REPO/src"
export IYI_PATH="$PWD/lib:$REPO/share/iyi/src:$REPO/share/iyi/crystal:$REPO/src"

$REPO/bin/iyi run --crystal app.iyi
```

```sh
curl localhost:3000/
curl localhost:3000/hello/dunya
curl 'localhost:3000/search?q=iyi'
curl -X POST -H 'Content-Type: application/json' -d '{"text":"ilk not"}' \
     localhost:3000/notes
curl localhost:3000/notes
```

`PORT=8080 iyi run --crystal app.iyi` moves it.

## Across a boundary

The second build never opens kemal's source. Each shard is compiled once into
a `.iyimod` — its declarations and its object code — and the program is built
against those. That is the boundary this compiler exists for: a module is
compiled against its dependencies' *declarations*, never their bodies.

Four boundaries, because kemal has three dependencies of its own, and in
dependency order — each one is bound against the ones already written. One
command does the four:

```sh
$REPO/bin/iyi bind
```

```
binding 4 shards into mods/, in dependency order:
  radix (Radix) — mods/radix.iyimod
  backtracer (Backtracer) — mods/backtracer.iyimod
  exception_page (ExceptionPage) — mods/exception_page.iyimod
  kemal (Kemal) — mods/kemal.iyimod
```

It reads `lib/` as `shards install` left it, orders the shards by their own
`shard.yml` dependencies, reads each root namespace off its entry file, and
runs two steps per shard as itself: `tool bind` writes the declarations,
then a build of the keep file it wrote fills in the object code. A getter
whose body is one instance variable is inlined at every call site and emits
no symbol, which is right for a whole program and wrong for code somebody
else links against — the fill build's `--iyi-keep` is what forces it out.
By hand, that is the loop `bench/kemal_serves.sh` used to write out:
`iyi tool bind --crystal -e Root --emit-bind mods --use-iyimod mods
lib/x/src/x.cr`, then `iyi build --crystal --iyi-keep Root --emit-bind .
x_keep.cr` inside `mods/`. A shard whose entry declares no top-level
module is named in the output and left to that pair.

Then the program, with its one line changed:

```sh
sed 's/^require "kemal"$/import kemal/' app.iyi > app_artifact.iyi
$REPO/bin/iyi build --crystal --use-iyimod mods -o app_artifact app_artifact.iyi
PORT=3001 ./app_artifact
```

`require` reads source; `import` reads an artifact. That line is the whole
difference, and the responses are byte-identical. `bench/kemal_serves.sh` is
this file with a gate around it, `iyi bind` included.

## What this is standing on

Every part of `app.iyi` was, at some point, a boundary that did not carry:
`get` is a top-level `def` a macro loop writes whose block returns `_`, so
neither it nor its body has a symbol and both travel as text; `env.params` is
a field kemal adds to `HTTP::Server::Context`, a class the library owns and no
boundary carries; `error 404` has to land in kemal's own handler order; and
`Kemal.run` is written with no block, the overload whose `args` is untyped, so
it crosses as its body. SPEC.md Part V item 12 has the account, and
`bench/kemal_serves.sh` is this file with a gate around it.
