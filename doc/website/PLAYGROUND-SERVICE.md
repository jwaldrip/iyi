# The playground: an editor, a compile service, and the browser that runs it

The playground shipped as an evidence page: curated listings, recorded
diagnostics, a card proving the module printed what the native binary printed.
That material is good and it stays, but it is not a playground. A playground is
an editor you can type anything into, a control that runs it, and output.

This document is the contract. It is written before the engine so the service
and the page are built against the same thing rather than against each other's
guesses. Two parties: the compile service, built separately, and
a new `remote` engine added under `site/src/playground/engines/`, built here.

## The split, and why it is this way round

**The server compiles. The browser runs.** The service takes source and returns
a `wasm32-wasi` module. The page executes that module in the visitor's tab
against the WASI host already in `site/src/playground/engines/wasi-preview1.ts`,
which is proven: 13 recorded modules instantiate under it and 12 print output
byte identical to a native run.

Three reasons this is better than the obvious alternative of running the program
on the server too.

1. **The service never executes the visitor's program.** Compiling is a bounded
   job with a timeout. Running arbitrary programs is a sandbox, a resource
   budget, an egress policy and an abuse surface, and none of that has to exist
   if the program runs in the tab that asked for it.
2. **The execution path stays one path.** A curated sample and a program a
   visitor typed are the same bytes flowing through the same host, so a defect
   in either is a defect in both and cannot hide on one side.
3. **The digest discipline survives.** Every module the page runs is checked
   against a digest before instantiation.

The cost is honest and goes in the UI: source leaves the machine to be compiled.
Nothing else does.

## Before anything else: compiling untrusted source is code execution

This is the finding that should shape the service, and it is measured in this
tree rather than assumed.

`src/compiler/iyi/macros/methods.cr` dispatches these at **compile time**:

- line 70, `when "system", "`"`, reaching `interpret_system`, whose body at
  line 256 is `` result = `#{cmd}` ``. A shell command, run by the compiler.
- line 78 and 80, `read_file` and `read_file?`. Any path the compiler can read.
- line 54, `env`. The service's own environment.
- line 82, `run`, reaching `interpret_run`, which at line 325 calls
  `@program.macro_run(filename, run_args)`: it **compiles and executes another
  program** and substitutes its standard output into the source being compiled.

So a POST of arbitrary iyi source to a compile service is remote code execution
by design, not by defect. The service must therefore either disable the macro
methods that reach the host, or run each compile inside a disposable sandbox
with no network egress, no secrets in its environment, a read only filesystem
apart from a scratch directory, a CPU and memory cap, and a hard timeout.
Whichever is chosen, say which in the health response so the page can state it,
because a visitor pasting code into a box deserves to know what the other end
does with it.

The feasibility report reached the same macro method from the other direction:
`doc/website/PLAYGROUND-FEASIBILITY.md` names `interpret_system` as blocker 4,
the shell out that a wasm front end cannot have.

## Endpoints

Two, versioned, JSON, no cookies, no credentials.

### `GET /v1/health`

Cheap, cacheable for a short window, and the only call the page makes before a
visitor asks for anything.

```json
{
  "ok": true,
  "compiler": {
    "version": "iyi 0.3.0-dev (built on Crystal 1.22.0-dev [af509de9e] (2026-08-23))",
    "commit": "3975a179fc5d0c56572148c1f6ce46d5627da046",
    "target": "wasm32-wasi"
  },
  "limits": {
    "max_source_bytes": 65536,
    "max_files": 8,
    "compile_timeout_ms": 15000
  },
  "sandbox": "each compile runs in a disposable container with no network egress and a 15 s cpu cap"
}
```

`compiler.commit` is the repository commit the service's compiler was built
from. The page prints it beside a run, because a result whose compiler is
anonymous is a result nobody can reproduce. `sandbox` is a sentence in the
service's own words, rendered verbatim in the provenance rail, in the same slot
where an engine's `notes` already go.

### `POST /v1/compile`

Request:

```json
{
  "files": [{ "path": "main.iyi", "text": "module main\n\nputs \"hello\"\n" }],
  "entry": "main.iyi",
  "want": "run",
  "flags": [],
  "client": "iyi-site 919b9f115"
}
```

- `files` mirrors `SourceFile[]` in `site/src/playground/types.ts`, so the shell
  hands the engine what the engine hands the service. `path` is load bearing:
  in iyi a module's path is its file's path, so multi file programs and their
  `import` edges work with no new concept.
- `entry` must be one of the `path` values. The service does not infer it.
- `want` is one of `run`, `emit-iyimod`, `mod-dump`, `format`, and it is the
  same vocabulary as `Capability` in `types.ts`. A service that implements only
  `run` returns `unsupported_want` for the rest, and the page disables those
  controls from the health response rather than discovering it on a click.
- `flags` is passed through untouched. A flag the service will not honour is a
  refusal, never a silent drop, because dropping `--release` and then reporting
  a duration is a measurement lie.
- `client` is a build identifier for the service's log. No visitor identifier,
  no cookie, no fingerprint.

Response, `200`, for any compile that actually ran, whether or not the program
was accepted:

```json
{
  "ok": false,
  "want": "run",
  "diagnostics": [
    {
      "severity": "error",
      "path": "main.iyi",
      "line": 7,
      "column": 6,
      "message": "Int32 does not implement Greet, required by `T` in `announce`",
      "rule": "R-3",
      "raw": "In main.iyi:7:6\n\n 7 | puts announce(42)\n          ^-------\nError: Int32 does not implement Greet, required by `T` in `announce`\n"
    }
  ],
  "stderr": "the compiler's complete output, verbatim",
  "compiler": { "version": "...", "commit": "...", "target": "wasm32-wasi" },
  "compile_ms": 812
}
```

and on success with `want: "run"`:

```json
{
  "ok": true,
  "want": "run",
  "diagnostics": [],
  "module": {
    "wasm_base64": "AGFzbQEAAAA...",
    "bytes": 85768,
    "sha256": "7822e287ac298c40e4e80ed356b7d18f13d809693eb739068f11d7e7b8b36777"
  },
  "stderr": "",
  "compiler": { "version": "...", "commit": "...", "target": "wasm32-wasi" },
  "compile_ms": 1204
}
```

`want: "emit-iyimod"` returns `artifact` with the same three fields plus a
`name`. `want: "mod-dump"` and `want: "format"` return `text`.

Four rules the service is held to, each because the page makes a claim that
depends on it.

1. **`raw` is verbatim.** The caret line, the leading spaces, the `Error:`
   prefix, unmodified. The page renders `raw` and treats the structured fields
   as an index into it. A diagnostic on this site is a recording of a real run,
   and reflowing it would make it a paraphrase.
2. **Structured fields are parsed, never invented.** If the service cannot
   parse a location out of `raw`, `path`, `line` and `column` are `null` and
   `raw` still arrives. `rule` is `null` unless the compiler actually cited a
   rule. Three of the eight recorded diagnostics in `site/records/diagnostics.json`
   cite no rule, and inventing one for them would be a fabrication the page
   would then display in a cited footer.
3. **`sha256` is of the exact bytes in `wasm_base64`.** The engine recomputes
   it and refuses on a mismatch, which catches a truncating proxy and keeps the
   digest rule the page already states.
4. **`ok` is about the requested stage, not about the transport.** A program the
   compiler rejected is `200` with `ok: false`. The service failing is a non
   2xx. The page has to tell "your program is broken" from "we are broken",
   because those are different sentences and only one of them is the visitor's
   problem.

### Errors

Non 2xx, always this shape:

```json
{ "error": { "code": "too_large", "message": "source is 91 KB, the limit is 64 KB", "limit_bytes": 65536 } }
```

Codes: `too_large` (413), `unsupported_want` (400), `bad_request` (400),
`rate_limited` (429, with `retry_after_seconds`), `timeout` (504),
`internal` (500). Anything else the engine treats as unreachable.

### CORS

The page is served from `https://jwaldrip.github.io` and from
`http://localhost:4321` and `http://localhost:4330` in development. The service
answers `OPTIONS` and sets `Access-Control-Allow-Origin` for those origins,
`Access-Control-Allow-Headers: content-type`, and no
`Access-Control-Allow-Credentials`. A wildcard is acceptable since there is no
credential to protect, and the absence of one is the point.

## The engine

A `remote` engine under `site/src/playground/engines/`, implementing `PlaygroundEngine`,
registered in `registry.ts` per the instructions already at the top of that
file. Nothing about the slot changes.

- The endpoint is a build time value, `PUBLIC_IYI_COMPILE_ENDPOINT`, read
  through `import.meta.env`. Empty is a real state, not a misconfiguration:
  this build has no compile service, and the page says so.
- `capabilities()` stays synchronous, pure and node safe, because the static
  build calls it. It reports `compile`, `run` and `diagnostics`.
- `ready()` calls `GET /v1/health` once, with a timeout, and records the result.
  It does not reject when the service is down, because the engine still works
  for curated samples, and a rejection would make the page show a fault where
  there is a degraded but honest state.
- `run()` with source that matches a curated sample byte for byte skips the
  service entirely and executes the recorded module, digest checked against
  `site/records/wasm/manifest.json`, exactly as today.
- `run()` with anything else posts to the service, verifies the digest of what
  came back, and hands the bytes to the same WASI host. Diagnostics stream as
  `diagnostic` events. A rejected program ends with no `exit` event, because
  nothing ran and there is no status to report.
- Service unreachable, with source that needs it: one `unsupported` event whose
  capability is `compile` and whose reason names the endpoint and what happened.
  No spinner, no silent fallback to a sample, no invented output.

## The page

Editor first. `site/src/pages/playground/[...sample].astro` keeps its routes so
every link the lessons already emit keeps working, but a route now means "open
the editor with this sample in it" rather than "a page about this sample".

```
  masthead
  ------------------------------------------------------------------
  playground                          [ service: answering, iyi 0.3.0-dev ]
  Type iyi. It compiles on a real compiler and runs in this tab.
  ------------------------------------------------------------------
  [ Run  (Cmd or Ctrl + Enter) ]  [ sample v ]  [ Share ]  [ Reset ]
  ------------------------------------------------------------------
  editor                              | output
  main.iyi                            | stdout and stderr as they arrive
  (colouring from the compiler's      | exit status and wall clock
   own lexer for a loaded sample,     |
   plain ink for text you typed,      |-----------------------------
   because there is no lexer here)    | diagnostics
                                      | verbatim, caret exact, rule cited
  ------------------------------------------------------------------
  provenance rail: which compiler, which commit, what the service does
  with your source, and a link to the evidence page
```

- Below 62rem the two panes stack, editor first.
- The service badge has four states and never guesses: `not configured in this
  build`, `checking`, `answering, <compiler version>`, `not answering`.
- Colouring: a loaded sample renders through the recorded token stream from the
  compiler's own lexer. Text a visitor typed renders as plain ink, because
  there is no lexer in the page and painting one program's tokens over another
  program's characters is the defect the existing staleness gate exists to
  prevent. When the service is answering it can return tokens later, and that is
  an engine change and nothing else.

## Sharing

`#src=` in the fragment, base64url of the source, deflate compressed through
`CompressionStream("deflate-raw")` where the browser has it and uncompressed
otherwise, with `&entry=` when the entry is not `main.iyi`. A fragment is never
sent to a server, so a shared program stays between the people holding the link,
and no shortener, no database and no moderation queue comes into existence.

The limit is real and gets said in the UI next to the control: browsers and
intermediaries stop being reliable somewhere past about 8 KB of URL, so the
Share control refuses above a fixed encoded size and says how far over it is.

## What moves, and where it goes

The evidence material is the site's character and none of it is deleted.

- The recorded diagnostics table, the byte identical proof card, and the "what
  is real here, precisely" section move to `/playground/evidence/`, linked from
  the playground's provenance rail and from the lessons.
- The lessons keep rendering their own recorded diagnostics inline, which is
  where a recording teaches best: beside the rule it breaks.
- The recorded modules keep their manifest, their digests and their gates. They
  are what makes the page work when the service does not.

## What this does not change

`site/src/playground/types.ts`'s hard constraint block still binds. The page is
not cross-origin isolated, so no `SharedArrayBuffer`, no wasm threads, no
synchronous standard input through `Atomics.wait`. Modules the page did not
compile in this session are digest checked before instantiation. Every gate
already proven stays, and the new paths are held to the same rule: no
transcribed number, no fabricated output, no control that does nothing.
