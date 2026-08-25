/**
 * The slot itself. One engine, registered explicitly, resolved in one place.
 *
 * There is no dynamic import, no glob of a directory, and no auto discovery.
 * The shell reads the active engine twice, once in node during the static
 * build to decide which controls to render, and once in the browser to run
 * them, and those two reads have to agree. A conditional or lazily resolved
 * engine would let the built HTML claim capabilities the running page does not
 * have, which is the precise failure this playground is designed not to have.
 * So registration is a plain module scope call, and it is the same on both
 * sides.
 *
 * ===========================================================================
 * TO WIRE A REAL ENGINE IN, do exactly this and nothing else:
 *
 *   1. Add `src/playground/engines/<name>.ts` exporting one object that
 *      implements `PlaygroundEngine` from `../types`. Read the HARD CONSTRAINT
 *      block at the top of `types.ts` first: the page is not cross-origin
 *      isolated, so `SharedArrayBuffer`, wasm threads and `Atomics.wait` are
 *      unavailable, and `capabilities()` must be synchronous, pure, and safe
 *      to call in node with no browser globals. Do not touch `window`,
 *      `document` or `WebAssembly` at import time; do that work in `ready()`.
 *
 *   2. In THIS file, below the marker, import it and call
 *      `registerEngine(yourEngine)`. That is the whole wiring step.
 *
 *   3. Report only what the engine actually does. `capabilities().supported`
 *      is a whitelist, and leaving a capability out is the supported answer:
 *      the shell renders that control disabled with a mono note naming the
 *      missing capability, and the page stays honest. Put every caveat in
 *      `capabilities().notes`, which is rendered verbatim in the rail beside
 *      the playground.
 *
 * Nothing else changes. `src/components/Playground.astro` reads
 * `activeEngine().capabilities()` and shapes itself, and its client script
 * streams `run()` events into the output pane, so a conforming engine lights
 * up the existing UI without a markup change.
 * ===========================================================================
 */
import type { PlaygroundEngine } from "./types";
import { unavailableEngine } from "./engines/unavailable";

let registered: PlaygroundEngine | null = null;

/**
 * Install the engine. Called below for whatever this site ships, and callable
 * by a test or a local harness that wants to drive the shell with its own
 * engine before the shell reads it.
 *
 * Registering a second, different engine throws rather than winning silently:
 * two engines in a one engine slot means somebody did not read this file, and
 * a last write wins would make which one you get depend on import order.
 */
export function registerEngine(engine: PlaygroundEngine): void {
  if (registered !== null && registered !== engine) {
    throw new Error(
      `playground: ${registered.id} is already registered, so ${engine.id} ` +
        `cannot be. There is one slot. Replace the registerEngine call in ` +
        `src/playground/registry.ts rather than adding a second one.`,
    );
  }
  registered = engine;
}

/**
 * The engine the page talks to.
 *
 * Falls back to `unavailableEngine`, which is a real implementation that
 * claims no capabilities and emits one refusal naming what is missing. The
 * fallback is never null and never a stub that pretends: the caller cannot
 * forget to handle the empty case, because the empty case is an engine that
 * answers truthfully.
 */
export function activeEngine(): PlaygroundEngine {
  return registered ?? unavailableEngine;
}

/* ===========================================================================
 * ENGINE REGISTRATION.
 *
 * The engine below compiles what a visitor types by sending it to a compile
 * service, and runs the wasm32-wasi module that comes back in this page,
 * against the WASI preview1 host every recorded sample already runs under. It
 * claims compile, run and diagnostics.
 *
 * It degrades rather than breaking, and the degradation is a property of the
 * engine rather than of the page. A curated sample the visitor has not edited
 * runs from its recorded module with the manifest's digest behind it, which is
 * what keeps this page working when the service is down or when a build was
 * given no service at all. Anything else needs the service, and when the
 * service is not there the engine says so in one refusal naming the endpoint
 * rather than inventing output or spinning forever.
 *
 * `engines/wasi.ts` is still here and still exercised: this engine delegates
 * the recorded path to the same `executeWasm` it uses, and the two agree about
 * what running means because there is one implementation of it.
 * ========================================================================= */

import { remoteEngine } from "./engines/remote";
registerEngine(remoteEngine);
