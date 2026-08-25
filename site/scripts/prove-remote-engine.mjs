#!/usr/bin/env node
// Drives the remote engine through every branch it has, against the stub in
// `compile-stub.mjs`, and fails if any branch answers with something other
// than what the contract says it must.
//
//     node scripts/prove-remote-engine.mjs
//
// WHY THIS EXISTS RATHER THAN A UNIT TEST OF THE HAPPY PATH. The engine's whole
// job is telling four situations apart: the program was accepted, the program
// was refused, the compiler was killed, and the service is broken or absent.
// Every one of those is a different sentence on the page, and three of them
// only ever appear when something has gone wrong, which is exactly when nobody
// is watching. A harness that walks all of them is the only way the refusals
// are as tested as the success.
//
// It runs in node, against the real engine module, with a real HTTP server on
// the other end and real recorded wasm coming back over it. What it does not
// have is a browser, so `crypto.subtle`, `fetch`, `performance` and
// `WebAssembly` come from node's own globals, which are the same
// implementations V8 gives the page.

import { spawn } from "node:child_process";
import { registerHooks } from "node:module";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

/* The engine is TypeScript, which node strips for itself, but its imports are
 * extensionless the way a bundler expects and node's resolver is not a
 * bundler. This hook is the whole difference: a relative specifier that does
 * not exist gets `.ts` tried before node gives up. It is confined to this
 * harness, so nothing about how the site builds changes. */
registerHooks({
  resolve(specifier, context, nextResolve) {
    /* A bundler resolves `./x` to `./x.ts` and imports JSON with no ceremony.
     * Node does neither, so both are supplied here, and only here: nothing
     * about how the site builds changes. */
    if (specifier.endsWith(".json")) {
      return { ...nextResolve(specifier, context), importAttributes: { type: "json" } };
    }
    if (specifier.startsWith(".") && !/\.[a-z]+$/i.test(specifier)) {
      const from = context.parentURL ? dirname(fileURLToPath(context.parentURL)) : ".";
      if (existsSync(resolve(from, `${specifier}.ts`))) {
        return nextResolve(`${specifier}.ts`, context);
      }
    }
    return nextResolve(specifier, context);
  },
});

const here = dirname(fileURLToPath(import.meta.url));
const site = resolve(here, "..");
const PORT = 8791;
const ENDPOINT = `http://127.0.0.1:${PORT}`;

/* The engine reads its endpoint from import.meta.env at module load, which is
 * Vite's shape rather than node's, so it is supplied here before the import.
 * Astro rewrites these at build time for the browser; this is the node side of
 * the same value. */
process.env.PUBLIC_IYI_COMPILE_ENDPOINT = ENDPOINT;

const manifest = JSON.parse(
  readFileSync(resolve(site, "records", "wasm", "manifest.json"), "utf8"),
);
const hello = manifest.samples.find((entry) => entry.id === "hello");
if (!hello) throw new Error("the manifest has no hello sample to drive");

const failures = [];
const check = (name, condition, detail) => {
  if (condition) {
    console.log(`  ok    ${name}`);
    return;
  }
  console.log(`  FAIL  ${name}: ${detail}`);
  failures.push(`${name}: ${detail}`);
};

async function collect(engine, files, opts) {
  const events = [];
  for await (const event of engine.run(files, opts)) events.push(event);
  return events;
}

const kinds = (events) => events.map((event) => event.kind).join(",");
const text = (events, kind) =>
  events
    .filter((event) => event.kind === kind)
    .map((event) => event.text ?? event.reason ?? "")
    .join("");

async function withMode(mode, body) {
  const stub = spawn(
    process.execPath,
    [resolve(here, "compile-stub.mjs"), "--port", String(PORT), "--mode", mode],
    { stdio: ["ignore", "pipe", "inherit"] },
  );
  try {
    await new Promise((ready, broke) => {
      stub.stdout.on("data", (chunk) => {
        if (String(chunk).includes("compile stub on")) ready();
      });
      stub.on("exit", (code) => broke(new Error(`stub exited ${code}`)));
      setTimeout(() => broke(new Error("stub did not start")), 5000);
    });
    await body();
  } finally {
    stub.kill("SIGKILL");
    await sleep(50);
  }
}

/* A fresh module graph per mode, because the engine caches what health told
 * it, which is the correct behaviour and would otherwise leak between cases. */
async function engineFor(mode) {
  const url = `../src/playground/engines/remote.ts?mode=${mode}&t=${Date.now()}`;
  const module_ = await import(new URL(url, import.meta.url).href);
  return module_.remoteEngine;
}

console.log("remote engine, against the stub:");

/* 1. Accepted --------------------------------------------------------------
 * A program the stub accepts comes back as a module, is verified, runs, and
 * prints what the recorded module prints. */
await withMode("ok", async () => {
  const engine = await engineFor("ok");
  await engine.ready();
  const events = await collect(
    engine,
    [{ path: "main.iyi", text: "module main\n\nputs \"typed by hand\"\n" }],
    { entry: "main.iyi" },
  );
  check(
    "accepted: artifact then output then exit",
    /artifact/.test(kinds(events)) && events.at(-1)?.kind === "exit",
    kinds(events),
  );
  check(
    "accepted: the program's own output arrives",
    text(events, "stdout").includes(hello.nativeStdout.split("\n")[0]),
    JSON.stringify(text(events, "stdout").slice(0, 80)),
  );
  check(
    "accepted: exit code is the real one",
    events.at(-1)?.code === 0,
    String(events.at(-1)?.code),
  );
  check(
    "accepted: the compiler is named in the console",
    text(events, "stderr").includes("compiled by"),
    JSON.stringify(text(events, "stderr").slice(0, 120)),
  );
});

/* 2. Refused ---------------------------------------------------------------
 * A program the compiler rejected is diagnostics and no exit, because nothing
 * ran and there is no status to report. */
await withMode("reject", async () => {
  const engine = await engineFor("reject");
  await engine.ready();
  const events = await collect(
    engine,
    [{ path: "main.iyi", text: "module main\n\nbroken\n" }],
    { entry: "main.iyi" },
  );
  check(
    "refused: diagnostics arrive",
    events.some((event) => event.kind === "diagnostic"),
    kinds(events),
  );
  check(
    "refused: no exit event, because nothing ran",
    !events.some((event) => event.kind === "exit"),
    kinds(events),
  );
  const first = events.find((event) => event.kind === "diagnostic");
  check(
    "refused: the compiler's verbatim text is the message, caret included",
    typeof first?.message === "string" && first.message.includes("^"),
    JSON.stringify(first?.message?.slice(0, 80)),
  );
  check(
    "refused: a diagnostic that cited no rule carries null, not an invention",
    events
      .filter((event) => event.kind === "diagnostic")
      .every((event) => event.rule === null || typeof event.rule === "string"),
    JSON.stringify(events.filter((e) => e.kind === "diagnostic").map((e) => e.rule)),
  );
});

/* 3. Killed ----------------------------------------------------------------
 * 200 with ok false and error.code timeout: the compiler ran and was stopped,
 * and the cause is the program, so it is not reported as a broken service. */
await withMode("timeout", async () => {
  const engine = await engineFor("timeout");
  await engine.ready();
  const events = await collect(
    engine,
    [{ path: "main.iyi", text: "module main\n\nslow\n" }],
    { entry: "main.iyi" },
  );
  check(
    "killed: reported as the compiler stopping, not as the service failing",
    text(events, "stderr").includes("still working") &&
      !text(events, "unsupported").includes("could not be reached"),
    kinds(events) + " " + JSON.stringify(text(events, "stderr").slice(0, 100)),
  );
  check("killed: no exit event", !events.some((e) => e.kind === "exit"), kinds(events));
});

/* 4. The service's own failures -------------------------------------------- */
for (const [mode, needle] of [
  ["internal", "internal"],
  ["rate-limited", "rate limiting"],
  ["too-large", "too large"],
]) {
  await withMode(mode, async () => {
    const engine = await engineFor(mode);
    await engine.ready();
    const events = await collect(
      engine,
      [{ path: "main.iyi", text: "module main\n\nputs \"x\"\n" }],
      { entry: "main.iyi" },
    );
    check(
      `${mode}: one refusal naming what happened`,
      events.length === 1 &&
        events[0].kind === "unsupported" &&
        events[0].reason.toLowerCase().includes(needle),
      kinds(events) + " " + JSON.stringify(events[0]?.reason?.slice(0, 120)),
    );
  });
}

/* 5. An unshipped want ------------------------------------------------------ */
await withMode("unsupported", async () => {
  const engine = await engineFor("unsupported");
  await engine.ready();
  const events = await collect(
    engine,
    [{ path: "main.iyi", text: "module main\n" }],
    { entry: "main.iyi", want: "mod-dump" },
  );
  check(
    "unshipped want: refused, naming that want",
    events[0]?.kind === "unsupported" && events[0]?.capability === "mod-dump",
    JSON.stringify(events[0]),
  );
});

/* 6. Bytes that are not the bytes ------------------------------------------- */
for (const mode of ["corrupt", "truncated"]) {
  await withMode(mode, async () => {
    const engine = await engineFor(mode);
    await engine.ready();
    const events = await collect(
      engine,
      [{ path: "main.iyi", text: "module main\n\nputs \"x\"\n" }],
      { entry: "main.iyi" },
    );
    check(
      `${mode}: refuses to run a module whose digest does not match`,
      events[0]?.kind === "unsupported" &&
        events[0].reason.includes("sha256") &&
        !events.some((event) => event.kind === "exit"),
      JSON.stringify(events[0]?.reason?.slice(0, 140)),
    );
  });
}

/* 7. Unreachable ------------------------------------------------------------ */
{
  const engine = await engineFor("down");
  await engine.ready();
  const events = await collect(
    engine,
    [{ path: "main.iyi", text: "module main\n\nputs \"x\"\n" }],
    { entry: "main.iyi" },
  );
  check(
    "unreachable: one refusal naming the endpoint, and no invented output",
    events.length === 1 &&
      events[0].kind === "unsupported" &&
      events[0].reason.includes(ENDPOINT) &&
      !events.some((event) => event.kind === "stdout"),
    JSON.stringify(events[0]?.reason?.slice(0, 140)),
  );
  check(
    "unreachable: says curated samples still run",
    events[0]?.reason.includes("Curated samples still run"),
    JSON.stringify(events[0]?.reason?.slice(0, 140)),
  );
}

console.log();
if (failures.length > 0) {
  console.log(`remote engine: ${failures.length} branch(es) wrong`);
  for (const failure of failures) console.log(`  ${failure}`);
  process.exit(1);
}
console.log("remote engine: every branch answers what the contract says it must");
