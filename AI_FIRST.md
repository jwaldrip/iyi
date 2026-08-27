# iyi, AI-first: the 0.4.0 plan

**Status:** Plan. Nothing below is built unless it names the commit that
built it. The measurement that decides whether any of it worked is §5, and
it is written down before the work on purpose.

## 1. The thesis

An AI-first language is four properties, and they are tool properties
before they are language properties:

1. **Context economy.** A model editing code should read interfaces, not
   bodies. The context window is the new compile time: what a build reads
   in milliseconds, a model reads in dollars.
2. **Feedback quality.** An error message is a repair instruction. It is
   fast, it is structured, and a machine can act on it without a human
   translating.
3. **Verifiability.** "Done" is checkable, cheaply, per module — not by
   rebuilding the world and reading prose.
4. **Unambiguity.** One way to write a thing: a formatter that ends style,
   no open classes, an export surface that is written rather than
   inferred.

iyi holds 1 and 4 **by language rule, not by tooling effort**. R-1 makes a
module's interface a file; R-2 makes the export surface explicit; R-3
closes every type at its declaration. None of this can be retrofitted onto
Python or TypeScript — an open class has no interface file to serve. The
0.4.0 work is turning that accident-proof foundation into tool surface.

What already serves the thesis, measured elsewhere in this repository:
the 0.13 s edit-loop rebuild (README), `iyi mod dump` printing an exact
API from an artifact with the source deleted (III.7), `iyi mod diff`
answering "did my change break the interface" with `--exit-code`, error
messages that name the rule and the fix and the SPEC section (house style
throughout), and a gate culture in `bench/` where every claim has a
command that reproduces it.

## 2. The menu, by leverage over cost

| # | Work | Why it is AI-first | Cost |
|---|---|---|---|
| 1 | **`iyi api` — Exports as JSON** | III.7's own sentence: "A model writing iyi code needs exact signatures; given prose it invents them." `iyi mod dump` prints for humans today; a JSON form plus a `Docs` section in the artifact (doc comments — the one gap III.7 names) is hallucination-proof grounding, served from a local artifact, no registry required | small |
| 2 | **`iyi context <module>` — the context pack** | The minimal text a model needs to edit one module: the module itself plus its imports' *declarations only*. R-2 makes this a **defined set** — Go and Rust have no exact equivalent. Feeds any agent harness directly; cuts grounding tokens by orders of magnitude | small (the `mod dump` machinery is most of it) |
| 3 | **JSON diagnostics** | Measure whether the Crystal base's `--error-format json` survives in the fork; wire it if so, add it if not. An error an agent can parse is an error it can fix. House-style errors already carry rule + fix + SPEC reference; add `spec_section` and `suggested_edit` fields and the style becomes machine-readable | small–medium |
| 4 | **`iyi test`** | The agent's verify loop. Invent no framework: this repository's own gate culture is the answer — a test is a plain iyi program with asserts and an exit-code contract. `iyi test` compiles and runs `*_test.iyi`, collects exit codes. Zero prelude lines, no ceiling pressure | medium |
| 5 | **Daemon → LSP** (III.8 #2) | The spec's own finding: the daemon was measured against the wrong consumer — "an editor session asks thousands of questions where a build asks one." Module-local type checking gives iyi an LSP **Crystal cannot have**. Agents speak LSP too | large |
| 6 | **`iyi.sum`** (III.7 step 2) | The trust half of AI-first: if a model writes the `require` line, the tool must prove that what arrived is what arrived last time. Supply chain matters more in the agent era, not less — the thing writing code can also be persuaded | small–medium |
| 7 | **Panics** (III.1.4) | Generated code that crashes should kill the *task*, not the process; `group` is already the boundary. Honest cost: unwinding, which the prelude's "nothing here unwinds" saving has to buy back | large |
| 8 | **The sandbox story** | Already true, just unwritten: zero-dependency static binaries plus the wasm32 target are the cheapest container for running untrusted generated code. A SPEC section and a wasmtime gate | small (mostly prose) |

**Built since this table was written**, naming the commits its status rule
demands:

- **1, the JSON half** — `iyi mod dump --json` (`649113a75`): exact
  signatures with their `rendered` spelling, types with fields, impls,
  the interface hash they are keyed by. The `Docs` section (doc comments
  in the artifact) is **not** built; the row stays open by that much.
- **2** — `iyi mod context FILE.iyi [--json]` (`649113a75`): every
  import's surface, no bodies, each import compiled *alone* — R-1 worn as
  a tool — so a half-broken tree still grounds.
- **3** — `iyi build -f json` was inherited and already worked, measured
  rather than assumed; what was added is the `spec` field (`c2e6529f2`),
  the SPEC sections an error cites, as data. `suggested_edit` is not
  built: errors do not carry structured edits, and inventing them would
  be prose wearing a schema.
- **6** — `iyi.sum` (`8d8b266fd`): tree-hashed checkouts, tool-written,
  tamper-refusing, and one rule it taught — a checkout is read-only,
  because the verifier caught its own footprint within the hour. The
  same hour caught item 3's first draft linking PCRE2 into the compiler:
  `bench/dependency_floor.sh` refused it by name, which is §5's culture
  already paying for itself.

All four are gated in `bench/packages_resolve.sh`.

Free advertising, no work: `iyi mod diff --exit-code` already answers the
agent question "did I break the API"; document it as a harness contract.

## 3. The recommended 0.4.0 cut

The release body is already in the tree: structured concurrency in
III.4.8's order (scheduler, cancellable primitives, `group`, rendezvous
`Channel`, `select`, the typed group), and III.7 step 1 (`iyi.mod`, MVS, a
git fetcher, offline-gated). On top of that, ship **1 + 2 + 3 + 6** —
together they are one sentence:

> **iyi is the first language a model can read, verify and trust:
> interfaces are data, errors are instructions, dependencies are hashed.**

Deferred, with reasons:

- **5 (LSP)** is 0.5.0's spine — large, and half-designed in III.8 #2
  already (the daemon's socket, framed protocol and pre-analysed prelude
  state exist; what it lacks is a `Program` kept between requests).
- **7 (panics)** belongs to the same wave as threads and the owned
  collector (`GC_DESIGN.md`), because unwinding, task boundaries and
  stack ownership are one design conversation.
- **4 (`iyi test`)** fits wherever it lands; it is cheap and closes the
  agent loop, but it gates nothing the bench scripts do not already gate.

## 4. What not to build

- **No prompt files, no "AI mode".** The language is the interface; a
  model is a consumer like any other. Anything that would fork behaviour
  by consumer is the open-class mistake wearing a new coat.
- **No prose-first docs endpoint.** Signatures are the grounding; prose
  is commentary. The `Docs` section rides the artifact so that the two
  cannot drift apart.
- **No benchmark theatre.** One measured claim beats ten plausible ones —
  which is §5.

## 5. The gate, written before the work

"AI-first" is a claim, so it gets what every claim here gets: a command
that can refuse it. The measurement, to live in `bench/`:

> Same task, same model, twice: once grounded with `iyi context`'s pack,
> once with raw files. Count (a) grounding tokens and (b) rounds until the
> build is green. The pack must win on both, by margins the script names,
> or the claim comes off the README.

Until that script exists and passes, nothing in this file is quoted
anywhere as fact.
