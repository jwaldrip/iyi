/**
 * The engine that compiles on a service and runs in this page.
 *
 * THE SPLIT, and why it is this way round. The server compiles. The browser
 * runs. `POST /v1/compile` takes source and answers with a `wasm32-wasi`
 * module; this engine hands those bytes to the WASI host in
 * `wasi-preview1.ts`, the same host the recorded modules already run under.
 * The service never executes the visitor's program, so it needs no sandbox for
 * running, no resource budget and no egress policy for it; the execution path
 * stays one path, so a defect in it is a defect for a curated sample and for a
 * typed program alike and cannot hide on one side; and every module this page
 * instantiates is still checked against a digest first. The contract is
 * `doc/website/PLAYGROUND-SERVICE.md` and this file implements the engine half
 * of it.
 *
 * THE COST, and it goes in the UI rather than in this comment: source leaves
 * the machine to be compiled. Nothing else does. The service states in its own
 * words what it does with that source, in `sandbox` on the health response, and
 * the page renders that sentence verbatim rather than writing a reassurance
 * nobody measured. If the field is absent the page says the service did not
 * state its containment.
 *
 * WHY COMPILING SOURCE IS ITSELF CODE EXECUTION. iyi's macro methods reach the
 * host at compile time: `src/compiler/iyi/macros/methods.cr` dispatches `env`,
 * `read_file`, `read_file?`, `system` and the backtick form through
 * `interpret_system`, and `run` through `interpret_run`, which calls
 * `macro_run` to compile and execute another program and substitute its output
 * into the source being compiled. So a POST of arbitrary iyi to a compile
 * service is remote code execution by design rather than by defect, the service
 * must contain it, and a program that reaches the host at compile time may
 * therefore behave differently here than in a local build. The page says that
 * where a visitor reads it, not here.
 *
 * WHAT THIS ENGINE WILL NOT DO. It will not run a module whose sha256 does not
 * match what the response claimed, because a truncating proxy would otherwise
 * turn into a silent miscompile. It will not fall back to a curated sample when
 * the service is unreachable and the visitor typed something: that would be
 * output the visitor's program did not produce. It will not synthesise an exit
 * status for a program that never started. Every one of those refusals arrives
 * as one `unsupported` event naming the capability it could not honour, which
 * is the contract's own answer for a control that cannot do its job.
 */
import type {
  Capabilities,
  Capability,
  PlaygroundEngine,
  RunEvent,
  RunOptions,
  SourceFile,
} from "../types";
import { curatedSamples, findSample, wasmProvenance } from "../samples";
import { recordedDiagnostics } from "../diagnostics";
import { executeWasm, nextFrame, sha256Hex } from "./execute";

/* ---------------------------------------------------------------------------
 * The endpoint, and the empty case
 * ------------------------------------------------------------------------- */

/**
 * Where the compile service is, decided when the site is built.
 *
 * A build time value rather than a runtime one because `capabilities()` has to
 * answer the same way in node during the static build and in the browser
 * afterwards. If those two disagreed, the built HTML would render controls the
 * running page cannot honour, which is the one failure the whole
 * `playground/` directory is arranged to prevent.
 *
 * EMPTY IS A REAL STATE. A build with no endpoint is not misconfigured: it is a
 * build with no compile service, which is what a fork, a preview of this branch
 * and anyone's local checkout all are until one is deployed. The page says so
 * on the badge, the engine claims no `compile` capability, and the thirteen
 * recorded samples still run. Treating it as an error would put a fault on the
 * page where there is a smaller playground.
 */
/* Vite defines `import.meta.env` and TypeScript does not know it exists when
 * this module is loaded outside a Vite build. The widened view is named here,
 * with its reason, rather than asserted inline at the read.
 *
 * The `process.env` fallback is what lets `site/scripts/prove-remote-engine.mjs`
 * drive this engine in plain node against a stub, which is the only place
 * every refusal branch is exercised. It cannot reach the browser, because
 * `process` is not defined there. */
const meta = import.meta as unknown as {
  env?: Record<string, string | undefined>;
};

const configured: Record<string, string | undefined> = {
  ...((typeof process !== "undefined" ? process.env : undefined) ?? {}),
  ...(meta.env ?? {}),
};

export const compileEndpoint: string = (
  configured.PUBLIC_IYI_COMPILE_ENDPOINT ?? ""
)
  .trim()
  .replace(/\/+$/, "");

/** Whether this build was given a service at all. */
export const hasCompileService = compileEndpoint !== "";

/* ---------------------------------------------------------------------------
 * The wire, as the contract writes it
 * ------------------------------------------------------------------------- */

/** `GET /v1/health`, the only call made before a visitor asks for anything. */
export interface Health {
  ok: boolean;
  compiler: { version: string; commit: string; target: string };
  limits?: {
    max_source_bytes?: number;
    max_files?: number;
    compile_timeout_ms?: number;
  };
  /**
   * One sentence in the service's own words about what it does with submitted
   * source. Optional on the wire because a service may not answer it, and the
   * page must be able to tell "it said nothing" apart from "it said it is
   * contained". Never written by this page on the service's behalf.
   */
  sandbox?: string;
  /**
   * Which `want` values the service implements, so the page can shape itself
   * from the answer rather than discovering a refusal on a click. Optional
   * because the contract's health example predates it; absent means the engine
   * assumes only what the contract guarantees, which is `run`.
   */
  wants?: string[];
}

interface CompilerStamp {
  version: string;
  commit: string;
  target: string;
}

interface WireDiagnostic {
  severity?: string;
  path?: string | null;
  line?: number | null;
  column?: number | null;
  message?: string;
  rule?: string | null;
  raw?: string;
}

interface WireError {
  code?: string;
  message?: string;
  limit_bytes?: number;
}

interface CompileResponse {
  ok?: boolean;
  want?: string;
  diagnostics?: WireDiagnostic[];
  module?: { wasm_base64?: string; bytes?: number; sha256?: string };
  artifact?: { name?: string; wasm_base64?: string; bytes?: number; sha256?: string };
  text?: string;
  stderr?: string;
  compiler?: CompilerStamp;
  compile_ms?: number;
  error?: WireError;
}

/**
 * `POST /v1/lex`, the addition that closes the colouring gap.
 *
 * The page has no lexer and must not grow one: a second grammar drifts from the
 * compiler's silently, and the drift shows up as a keyword the site does not
 * think is a keyword. So the service exposes the compiler's own highlighter and
 * the page asks for a token stream on a debounce while someone types. The
 * response carries the highlighter's HTML, which is the same producer that
 * wrote `site/records/highlight.json`, so the live path and the recorded path
 * run through one renderer in `src/lib/tokens.ts` and cannot disagree.
 *
 * `tokens` is accepted as an alternative shape for a service that would rather
 * send a flat stream than markup. Both arrive at the same renderer.
 */
interface LexResponse {
  ok?: boolean;
  html?: string;
  tokens?: { cls?: string; kind?: string; text?: string }[];
  error?: WireError;
}

/* ---------------------------------------------------------------------------
 * Budgets and timeouts
 * ------------------------------------------------------------------------- */

/**
 * The editor's budget before the service has said its own.
 *
 * The same number the recorded engine published, for the same reason: a tab has
 * a memory ceiling, and a playground that dies on a large paste is a worse
 * answer than one that refuses. `capabilities()` cannot await the health
 * response, so this is the figure the built page renders; when health arrives
 * with a smaller `max_source_bytes` the engine holds itself to that instead and
 * says which it used in the refusal.
 */
const MAX_SOURCE_BYTES = 64 * 1024;

/** How long the page waits on health before calling the service unanswered. */
const HEALTH_TIMEOUT_MS = 4_000;

/** How long the page waits on a compile before giving up on the request. */
const COMPILE_TIMEOUT_MS = 30_000;

/** How long the page waits on a lex request. Short: it runs while typing. */
const LEX_TIMEOUT_MS = 3_000;

/**
 * The build identifier the service logs. No visitor identifier, no cookie, no
 * fingerprint: this names the site build so the service can tell its own
 * traffic apart, and nothing else.
 */
const CLIENT_ID = `iyi-site ${wasmProvenance.commit.slice(0, 9)}`;

/* ---------------------------------------------------------------------------
 * Capabilities
 * ------------------------------------------------------------------------- */

/**
 * The caveats, rendered verbatim in the rail beside the editor.
 *
 * Built once at module scope, and conditional on the endpoint only, which is a
 * build time value, so the list the built HTML carries is the list the browser
 * would produce. Anything that depends on the health response is not in here:
 * it is reported by `health()` and rendered by the page as it arrives, because
 * a caveat written before the service answered would be this page's guess at
 * the service's own words.
 */
function notes(): string[] {
  const lines: string[] = [];
  if (!hasCompileService) {
    lines.push(
      "this build has no compile service, so nothing here compiles: the " +
        "thirteen recorded samples still run, and a program you type cannot " +
        "be built. Set PUBLIC_IYI_COMPILE_ENDPOINT at build time to point " +
        "this page at one.",
    );
  } else {
    lines.push(
      `source you run leaves this machine: it is posted to ${compileEndpoint} ` +
        `to be compiled, and the module that comes back is executed here. ` +
        `Nothing else leaves, and a shared link is a URL fragment, which a ` +
        `browser never sends to a server.`,
    );
    lines.push(
      "compiling iyi is itself code execution: macro methods reach the host " +
        "at compile time (system and the backtick form, read_file, env, and " +
        "run, which compiles and executes another program), so the service " +
        "has to contain them and a program that reaches the host may behave " +
        "differently here than in a local build",
    );
  }
  lines.push(
    "source that is byte for byte one of the recorded samples skips the " +
      "service and runs the recorded module, so a sample still runs when the " +
      "service does not",
  );
  lines.push(
    `every module this page instantiates is checked by sha256 first: a ` +
      `recorded one against site/records/wasm/manifest.json, a freshly ` +
      `compiled one against the digest the service sent with it`,
  );
  lines.push(
    "diagnostics on the evidence page are recorded, not live: the compiler " +
      "reports errors by raising, and raise on wasm32 does not unwind, so a " +
      "compiler compiled for this page could not return a diagnostic to its " +
      "caller (doc/website/PLAYGROUND-FEASIBILITY.md). A diagnostic from the " +
      "service is live, and it is the same compiler on a machine that can " +
      "unwind.",
  );
  lines.push(
    "output arrives in the exact chunks fd_write produced, in that order, but " +
      "after _start returns: suspending a wasm call needs Atomics.wait on a " +
      "SharedArrayBuffer, and GitHub Pages cannot send the headers that would " +
      "make this document cross-origin isolated",
  );
  lines.push(
    "there is no stdin and no filesystem: reads from fd 0 report end of file " +
      "and every path call fails the way it would under a host that granted " +
      "no capabilities",
  );
  lines.push(
    "the wall clock of a run is a property of your browser on your machine, " +
      "coarsened by the same isolation rule, and is never a benchmark: the " +
      "project's measurements live in bench/",
  );
  return lines;
}

/**
 * What this engine claims, and why the list moves with the endpoint.
 *
 * `run` and `diagnostics` always: it runs recorded modules and it reports
 * compiler messages with a file, a line, a column and the rule they enforce.
 *
 * `compile` only when this build was given a service. The contract says the
 * engine reports `compile`, `run` and `diagnostics`, and it does, whenever
 * there is something behind the endpoint to honour it. With no endpoint,
 * claiming `compile` would put a build control on the page that can only ever
 * refuse, and `registry.ts` is explicit that a control which does nothing is a
 * lie told by an affordance. So the empty build gets the smaller playground,
 * which is the same rule the whole directory is built on, applied to the one
 * value that is known when the page is built.
 *
 * `format`, `emit-iyimod` and `mod-dump` are not claimed even with a service,
 * because `want` support is discovered from health rather than assumed, and a
 * capability claimed at build time cannot be withdrawn by an answer that
 * arrives later. Those three controls stay disabled with the missing capability
 * named under each, which is the honest interface until health is a build input
 * rather than a runtime one.
 */
const CAPABILITIES: Capabilities = {
  supported: hasCompileService
    ? (["compile", "run", "diagnostics"] as Capability[])
    : (["run", "diagnostics"] as Capability[]),
  maxSourceBytes: MAX_SOURCE_BYTES,
  notes: notes(),
};

/* ---------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

function moduleUrl(wasm: string): string {
  const base = (meta.env?.BASE_URL ?? "/").replace(/\/*$/, "/");
  return `${base}wasm/${wasm}`;
}

/* `sha256Hex` and `nextFrame` come from ./execute.ts, which is where the
 * execution path lives, so the digest this engine checks and the digest the
 * recorded engine checks are computed by one function. */

function decodeBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const encoder = new TextEncoder();

function byteLength(text: string): number {
  return encoder.encode(text).length;
}

/**
 * A `fetch` with a deadline that reports which of the two happened.
 *
 * A timeout and a refused connection are different facts about the service and
 * the page says which, so the reason a visitor reads names what actually went
 * wrong instead of a single word covering both.
 */
async function fetchWithin(
  url: string,
  init: RequestInit,
  ms: number,
): Promise<{ response: Response } | { failure: string }> {
  if (typeof fetch !== "function") {
    return { failure: "this page has no fetch, so the service cannot be reached" };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    return { response };
  } catch (error) {
    if (controller.signal.aborted) {
      return {
        failure: `no answer within the page's own deadline of ${ms / 1000} of a second times a thousand`,
      };
    }
    return {
      failure: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

/* ---------------------------------------------------------------------------
 * Health, asked once
 * ------------------------------------------------------------------------- */

/**
 * What the page knows about the service right now.
 *
 * `state` is the badge's four states and nothing else, so the page renders a
 * fact rather than deriving one: `absent` when this build has no endpoint,
 * `checking` before the first answer, `answering` when health parsed, and
 * `silent` when it did not. `since` is not a duration anyone reads, it is there
 * so the page can re-ask after a failure rather than deciding once and staying
 * wrong.
 */
export interface ServiceState {
  state: "absent" | "checking" | "answering" | "silent";
  endpoint: string;
  health: Health | null;
  /** Why it is silent, in the words of whatever failed. Null when it is not. */
  failure: string | null;
}

let service: ServiceState = {
  state: hasCompileService ? "checking" : "absent",
  endpoint: compileEndpoint,
  health: null,
  failure: null,
};

let asking: Promise<ServiceState> | null = null;

/** The current service state, without asking. Safe before `ready()`. */
export function serviceState(): ServiceState {
  return service;
}

/**
 * Ask the service how it is, once per tab, and remember the answer.
 *
 * Never rejects. A service that is down is a state the page renders, not an
 * exception the page handles, because the engine still works for the recorded
 * samples and a rejection would make the page show a fault where there is a
 * degraded but honest state.
 */
export function health(): Promise<ServiceState> {
  if (!hasCompileService) return Promise.resolve(service);
  if (service.state === "answering") return Promise.resolve(service);
  if (asking !== null) return asking;

  asking = (async () => {
    const url = `${compileEndpoint}/v1/health`;
    const attempt = await fetchWithin(
      url,
      { method: "GET", headers: { accept: "application/json" } },
      HEALTH_TIMEOUT_MS,
    );
    if ("failure" in attempt) {
      service = { ...service, state: "silent", health: null, failure: attempt.failure };
      asking = null;
      return service;
    }
    if (!attempt.response.ok) {
      service = {
        ...service,
        state: "silent",
        health: null,
        failure: `${url} answered ${attempt.response.status} ${attempt.response.statusText}`,
      };
      asking = null;
      return service;
    }
    let parsed: Health;
    try {
      parsed = (await attempt.response.json()) as Health;
    } catch (error) {
      service = {
        ...service,
        state: "silent",
        health: null,
        failure: `${url} answered something this page cannot parse as JSON: ${
          error instanceof Error ? error.message : String(error)
        }`,
      };
      asking = null;
      return service;
    }
    if (parsed?.ok !== true || typeof parsed?.compiler?.version !== "string") {
      service = {
        ...service,
        state: "silent",
        health: null,
        failure:
          `${url} answered JSON that is not a health response: the contract ` +
          `asks for ok and a compiler version, and a service that cannot ` +
          `name its own compiler cannot be quoted beside a run`,
      };
      asking = null;
      return service;
    }
    service = { ...service, state: "answering", health: parsed, failure: null };
    asking = null;
    return service;
  })();

  return asking;
}

/** Whether the answering service implements a `want`. */
export function serviceHandles(want: string): boolean {
  if (service.state !== "answering") return false;
  const wants = service.health?.wants;
  /* No list means the contract's guarantee and nothing more. `run` is what the
   * service ships for certain; anything else is discovered, and assuming it
   * would put a control on the page that answers 400. */
  if (!Array.isArray(wants)) return want === "run";
  return wants.includes(want);
}

/* ---------------------------------------------------------------------------
 * Lexing, for live colouring
 * ------------------------------------------------------------------------- */

/**
 * Ask the compiler's own lexer to colour what the visitor typed.
 *
 * Returns the highlighter's HTML, or null for every kind of no: no service, no
 * lex support, a refusal, a transport failure, a response that will not parse.
 * Null is not an error condition here. The page falls back to plain ink, which
 * is the state it was already in, and it says nothing to the visitor about it,
 * because a console line every time a keystroke outran a network round trip
 * would be noise about the page rather than information about the program.
 */
export async function lex(
  files: SourceFile[],
  entry: string,
): Promise<string | null> {
  if (!hasCompileService) return null;
  if (service.state !== "answering") return null;
  if (!serviceHandles("lex")) return null;

  const attempt = await fetchWithin(
    `${compileEndpoint}/v1/lex`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ files, entry, client: CLIENT_ID }),
    },
    LEX_TIMEOUT_MS,
  );
  if ("failure" in attempt) return null;
  if (!attempt.response.ok) return null;

  let parsed: LexResponse;
  try {
    parsed = (await attempt.response.json()) as LexResponse;
  } catch {
    return null;
  }
  if (parsed?.ok !== true) return null;
  if (typeof parsed.html === "string" && parsed.html !== "") return parsed.html;

  /* The flat stream shape, folded into the markup shape so the page has one
   * renderer. A token with no class is text the lexer did not classify, which
   * is exactly what the recorded markup carries as bare text. */
  if (Array.isArray(parsed.tokens)) {
    const escape: Record<string, string> = {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    };
    let html = "";
    for (const token of parsed.tokens) {
      const text = typeof token?.text === "string" ? token.text : "";
      if (text === "") continue;
      const safe = text.replace(/[&<>"']/g, (char) => escape[char]);
      const cls = token.cls ?? token.kind ?? "";
      html += cls === "" ? safe : `<span class="${cls}">${safe}</span>`;
    }
    return html === "" ? null : html;
  }
  return null;
}

/* ---------------------------------------------------------------------------
 * The engine
 * ------------------------------------------------------------------------- */

/** Recorded modules already fetched and verified in this tab, by sample id. */
const recorded: Record<string, { module: WebAssembly.Module; bytes: Uint8Array }> =
  {};

let cancelled = false;

/**
 * Running a module is not written here, and that is deliberate.
 *
 * `./execute.ts` holds it and both engines call it, because a curated sample
 * and a program the visitor typed are the same bytes flowing through the same
 * host: a defect in either is a defect in both and cannot hide on one side.
 * That is the second of the contract's three reasons for compiling on a
 * service and running here, and two copies of the function would quietly undo
 * it.
 *
 * `executeWasm` yields the artifact, then stdout and stderr in the order the
 * program wrote them, then either a real exit carrying a real wall clock or,
 * for a trap, one stderr line and NO exit event, because a trapped program has
 * no status and inventing one would be a fabrication.
 */

/**
 * Turn a wire diagnostic into the event the page renders.
 *
 * `raw` is what gets shown: the caret line, the leading spaces and the `Error:`
 * prefix exactly as the compiler printed them, because a diagnostic on this
 * site is a recording of a real run and reflowing it would make it a
 * paraphrase. The structured fields are an index into that text, so a service
 * that could not parse a location sends nulls and the event still carries the
 * compiler's own words. `rule` stays null unless the compiler cited one:
 * inventing a rule would be a fabrication the page would then display in a
 * cited footer.
 */
function toDiagnostic(
  wire: WireDiagnostic,
  fallbackPath: string,
): Extract<RunEvent, { kind: "diagnostic" }> {
  const raw = typeof wire.raw === "string" && wire.raw !== "" ? wire.raw : null;
  const message =
    typeof wire.message === "string" && wire.message !== ""
      ? wire.message
      : "the service sent a diagnostic with no message";
  return {
    kind: "diagnostic",
    file: wire.path ?? fallbackPath,
    /* Zero rather than a guess. The renderer prints `raw`, and a line number
     * the service could not parse is a number this page must not invent. */
    line: typeof wire.line === "number" ? wire.line : 0,
    column: typeof wire.column === "number" ? wire.column : 0,
    message: raw ?? message,
    rule: typeof wire.rule === "string" && wire.rule !== "" ? wire.rule : null,
  };
}

export const remoteEngine: PlaygroundEngine = {
  id: "remote-compile",
  label: hasCompileService
    ? "compiled by a service, run in this page"
    : "recorded modules only, no compile service in this build",

  /**
   * Check what would otherwise fail later for a reason the page could not
   * explain, then ask the service how it is.
   *
   * The two checks reject, because a browser with no WebAssembly and a page
   * with no SubtleCrypto are the engine being genuinely broken rather than
   * honestly limited. The health call does not, whatever it finds: a service
   * that is down is a state, and `ready()` rejecting would make the page show a
   * fault where there is a smaller playground.
   */
  async ready(): Promise<void> {
    if (typeof WebAssembly?.instantiate !== "function") {
      throw new Error(
        "this browser has no WebAssembly, so a wasm32-wasi module cannot be " +
          "instantiated here at all",
      );
    }
    if (typeof crypto?.subtle?.digest !== "function") {
      throw new Error(
        "this page has no SubtleCrypto, so a module's sha256 cannot be " +
          "checked. The engine will not run bytes it cannot verify are the " +
          "bytes it was promised.",
      );
    }
    await health();
  },

  capabilities(): Capabilities {
    return CAPABILITIES;
  },

  async *run(files: SourceFile[], opts: RunOptions): AsyncIterable<RunEvent> {
    cancelled = false;
    const want = opts.want ?? "run";

    /* Diagnostics on their own ------------------------------------------- */

    /* The evidence page asks for these and renders them beside the rule each
     * one enforces. They are a recording of the real compiler on real broken
     * programs, and the page says so in a sentence. A live diagnostic reaches
     * the page the other way, as part of a `run` that the service refused. */
    if (want === "diagnostics") {
      for (const diagnostic of recordedDiagnostics()) {
        if (cancelled) return;
        yield diagnostic;
      }
      return;
    }

    if (files.length === 0) {
      yield {
        kind: "unsupported",
        capability: want,
        reason: "there is no source to work on: the editor sent no files",
      };
      return;
    }

    const entry = opts.entry;
    if (!files.some((file) => file.path === entry)) {
      yield {
        kind: "unsupported",
        capability: want,
        reason:
          `the entry "${entry}" is not one of the files sent ` +
          `(${files.map((file) => file.path).join(", ")}), and this engine ` +
          `does not infer an entry point from ordering: a module's identity ` +
          `is its path, so guessing would be the one place it pretended to ` +
          `know something about the language`,
      };
      return;
    }

    /* The recorded path -------------------------------------------------- */

    /* Source that is byte for byte a curated sample runs the module the
     * compiler already produced from it, checked against the manifest. That is
     * what keeps a sample running when the service is down, and it costs the
     * page one sha256 of the editor's text rather than the quarter of a
     * megabyte of listings it would take to compare the text itself. */
    if (files.length === 1) {
      const digest = await sha256Hex(encoder.encode(files[0].text));
      /* `sourceSha256` is in the manifest, written by the recorder from the
       * file the module was built from, and verified against the tree on every
       * build by scripts/records.mjs. So this comparison is against the same
       * record that stands behind the module, rather than against a second
       * list of digests that could drift from it. */
      const sample =
        curatedSamples.find((entry_) => entry_.sourceSha256 === digest) ?? null;
      if (sample !== null) {
        if (want !== "run") {
          yield {
            kind: "unsupported",
            capability: want,
            reason:
              `this is ${sample.path} unchanged, and the recording holds the ` +
              `module it was built into rather than the pipeline that built ` +
              `it, so there is nothing here to answer ${want} with. Change a ` +
              `character and it goes to the compiler.`,
          };
          return;
        }
        yield* runRecorded(sample.id);
        return;
      }
    }

    /* The service path --------------------------------------------------- */

    if (!hasCompileService) {
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `this build of the site was given no compile service, so a program ` +
          `you typed cannot be built: PUBLIC_IYI_COMPILE_ENDPOINT was empty ` +
          `when the page was built. The thirteen recorded samples still run, ` +
          `because their modules ship with the site. Nothing was sent ` +
          `anywhere, and nothing was run.`,
      };
      return;
    }

    /* Health is asked once per tab and the answer is remembered, so this is a
     * network call only the first time. A service that never answered is
     * reported here rather than by a request that would fail the same way with
     * less to say about it. */
    const state = await health();
    if (state.state !== "answering") {
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `${compileEndpoint} is not answering, so the program you typed was ` +
          `not compiled and nothing ran: ${state.failure ?? "no reason given"}. ` +
          `The recorded samples still run. Nothing was invented in place of ` +
          `the output your program would have produced.`,
      };
      return;
    }

    const limit = state.health?.limits?.max_source_bytes ?? MAX_SOURCE_BYTES;
    const total = files.reduce((sum, file) => sum + byteLength(file.text), 0);
    if (total > limit) {
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `the service accepts ${limit} bytes of source and this is ${total}, ` +
          `so the request was not sent. The number is the service's own, from ` +
          `its health response.`,
      };
      return;
    }

    if (want !== "run" && !serviceHandles(want)) {
      yield {
        kind: "unsupported",
        capability: want,
        reason:
          `${compileEndpoint} does not implement ${want}. It says which wants ` +
          `it implements in its health response, and this page reads that ` +
          `rather than finding out on a click, so the control above is ` +
          `disabled rather than clickable and lying.`,
      };
      return;
    }

    if (cancelled) return;

    const attempt = await fetchWithin(
      `${compileEndpoint}/v1/compile`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          files,
          entry,
          want,
          flags: opts.flags ?? [],
          client: CLIENT_ID,
        }),
      },
      COMPILE_TIMEOUT_MS,
    );

    if (cancelled) return;

    if ("failure" in attempt) {
      /* A transport failure with no body at all is one of the two states the
       * page reports as the service's fault. The other is a 500. */
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `${compileEndpoint}/v1/compile could not be reached, so nothing was ` +
          `compiled and nothing ran: ${attempt.failure}`,
      };
      service = { ...service, state: "silent", failure: attempt.failure };
      return;
    }

    let body: CompileResponse | null = null;
    let bodyText = "";
    try {
      bodyText = await attempt.response.text();
      body = JSON.parse(bodyText) as CompileResponse;
    } catch {
      body = null;
    }

    /* Anything the engine cannot parse is treated as unreachable, per the
     * contract. A page that guessed at an unparseable body would be inventing
     * the service's answer. */
    if (body === null || typeof body !== "object") {
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `${compileEndpoint}/v1/compile answered ${attempt.response.status} ` +
          `with ${bodyText.length} characters this page cannot parse as the ` +
          `contract's JSON, so it is treated as unreachable rather than ` +
          `guessed at`,
      };
      return;
    }

    /* The body is the discriminator and the status is for caches and proxies,
     * so every branch below reads the body. */

    if (body.error !== undefined && body.error?.code !== "timeout") {
      const code = body.error.code ?? "an error with no code";
      const detail = body.error.message ?? "no message";
      yield {
        kind: "unsupported",
        capability: "compile",
        reason:
          `${compileEndpoint} refused the request: ${code}, ${detail}` +
          (attempt.response.status === 429
            ? `. The service rate limits on the peer address, so this is your ` +
              `own budget rather than anyone else's.`
            : ""),
      };
      return;
    }

    /* Diagnostics first, whether the compile succeeded or failed: warnings
     * belong beside a program that ran, and errors belong instead of one. */
    for (const wire of body.diagnostics ?? []) {
      if (cancelled) return;
      yield toDiagnostic(wire, entry);
    }

    if (body.error?.code === "timeout") {
      /* A timeout's cause is the program, so it goes where "your program is
       * broken" goes rather than where "we are broken" goes. No exit event:
       * nothing ran to completion, so there is no status. */
      yield {
        kind: "stderr",
        text:
          `${body.error.message ?? "the compiler was killed by the service's timeout"}\n`,
      };
      return;
    }

    if (body.ok !== true) {
      /* The compiler ran and refused the program. The diagnostics above are the
       * result. No exit event, because nothing ran and there is no status to
       * report. */
      if ((body.diagnostics ?? []).length === 0) {
        yield {
          kind: "unsupported",
          capability: "compile",
          reason:
            `${compileEndpoint} refused the program without saying why: the ` +
            `response carries neither a diagnostic nor an error code, and ` +
            `this page will not write a reason on the compiler's behalf` +
            (typeof body.stderr === "string" && body.stderr !== ""
              ? `. Its complete output was: ${body.stderr}`
              : ""),
        };
      }
      return;
    }

    if (cancelled) return;

    /* Text products: format and mod dump come back as text rather than bytes,
     * and they are the compiler's output, so they go to the console as it
     * wrote them. */
    if (want === "format" || want === "mod-dump") {
      if (typeof body.text !== "string") {
        yield {
          kind: "unsupported",
          capability: want,
          reason: `${compileEndpoint} answered ok for ${want} without any text`,
        };
        return;
      }
      yield { kind: "stdout", text: body.text };
      return;
    }

    const wire = want === "run" ? body.module : body.artifact;
    if (wire?.wasm_base64 === undefined || typeof wire.sha256 !== "string") {
      yield {
        kind: "unsupported",
        capability: want === "run" ? "run" : want,
        reason:
          `${compileEndpoint} answered ok but sent no module with a digest, ` +
          `and this engine will not run bytes it cannot check`,
      };
      return;
    }

    let bytes: Uint8Array;
    try {
      bytes = decodeBase64(wire.wasm_base64);
    } catch (error) {
      yield {
        kind: "unsupported",
        capability: "run",
        reason:
          `the module the service sent is not valid base64, so there are no ` +
          `bytes to run: ${error instanceof Error ? error.message : String(error)}`,
      };
      return;
    }

    const digest = await sha256Hex(bytes);
    if (digest !== wire.sha256.toLowerCase()) {
      /* Refuse. The contract makes the service compute this over the exact
       * bytes it put in `wasm_base64`, so a mismatch is a truncating proxy or a
       * corrupted transfer, and running it anyway would turn a network fault
       * into a silent miscompile. */
      yield {
        kind: "unsupported",
        capability: "run",
        reason:
          `the module arrived with ${bytes.length} bytes whose sha256 is ` +
          `${digest.slice(0, 16)}, and the service said its digest was ` +
          `${wire.sha256.slice(0, 16)}. Something between here and there ` +
          `changed the bytes, so they will not be run.`,
      };
      return;
    }

    if (want !== "run") {
      /* An artifact the page was asked to produce rather than execute. The
       * bytes are handed over so their size is checkable in this tab rather
       * than taken on trust. */
      yield {
        kind: "artifact",
        name: wire.name ?? `${entry}.iyimod`,
        bytes: bytes.length,
        data: bytes,
      };
      return;
    }

    /* Provenance, in the console, beside the run it belongs to. A result whose
     * compiler is anonymous is a result nobody can reproduce, and this is the
     * one place a visitor can see which compiler and which commit answered.
     * The rail carries the same facts for the service as a whole; this carries
     * them for this run, which is the thing they are about. */
    if (body.compiler?.version) {
      yield {
        kind: "stderr",
        text:
          `compiled by ${body.compiler.version}` +
          `${body.compiler.commit ? ` at commit ${body.compiler.commit.slice(0, 12)}` : ""}` +
          ` for ${body.compiler.target ?? "wasm32-wasi"}` +
          `${typeof body.compile_ms === "number" ? `, in ${body.compile_ms} ms on the service` : ""}\n`,
      };
    }

    if (typeof body.stderr === "string" && body.stderr !== "") {
      /* The compiler said something that was not a diagnostic. It is the
       * compiler's own output, so it is reported rather than dropped. */
      yield { kind: "stderr", text: body.stderr };
    }

    yield {
      kind: "artifact",
      name: `${entry.replace(/^.*\//, "").replace(/\.iyi$/, "")}.wasm`,
      bytes: bytes.length,
      data: bytes,
    };

    yield* executeWasm({
      bytes,
      name: "the module the service compiled",
      argv0: entry,
      isCancelled: () => cancelled,
    });
  },

  cancel(): void {
    cancelled = true;
  },

  dispose(): void {
    for (const key of Object.keys(recorded)) delete recorded[key];
    cancelled = false;
  },
};

/**
 * Fetch, verify and run one recorded module.
 *
 * Split out because it is the path that must keep working with no service at
 * all, and it is exactly the path the page has today: the module is fetched
 * from the site's own assets, its sha256 is checked against
 * `site/records/wasm/manifest.json`, and only then is it instantiated.
 */
async function* runRecorded(id: string): AsyncIterable<RunEvent> {
  const sample = findSample(id);
  if (sample === null) {
    yield {
      kind: "unsupported",
      capability: "run",
      reason: `"${id}" is not in the recording, so there is no module for it`,
    };
    return;
  }

  const held = recorded[sample.id];
  if (held !== undefined) {
    /* Already fetched and verified in this tab. `executeWasm` is handed the
     * compiled module so a second run measures execution rather than the
     * network and the compiler. */
    yield* executeWasm({
      bytes: held.bytes,
      name: sample.wasm,
      argv0: sample.path,
      isCancelled: () => cancelled,
      compiled: held.module,
    });
    return;
  }

  const url = moduleUrl(sample.wasm);
  const attempt = await fetchWithin(url, { method: "GET" }, COMPILE_TIMEOUT_MS);
  if ("failure" in attempt) {
    yield {
      kind: "unsupported",
      capability: "run",
      reason:
        `${url} could not be fetched, so there are no bytes to run: ` +
        `${attempt.failure}. The modules are copied into public/wasm/ by ` +
        `site/scripts/records.mjs at build time.`,
    };
    return;
  }
  if (!attempt.response.ok) {
    yield {
      kind: "unsupported",
      capability: "run",
      reason:
        `${url} answered ${attempt.response.status} ${attempt.response.statusText}, ` +
        `so there are no bytes to run.`,
    };
    return;
  }

  const bytes = new Uint8Array(await attempt.response.arrayBuffer());
  const digest = await sha256Hex(bytes);
  if (digest !== sample.sha256) {
    yield {
      kind: "unsupported",
      capability: "run",
      reason:
        `${url} served ${bytes.length} bytes whose sha256 is ` +
        `${digest.slice(0, 16)}, and the record says ${sample.bytes} bytes at ` +
        `${sample.sha256.slice(0, 16)}. This engine will not run a module it ` +
        `cannot show is the recorded one, because everything the page says ` +
        `about where that module came from would then be unfounded. ` +
        `Regenerate with ${wasmProvenance.command}.`,
    };
    return;
  }

  if (cancelled) return;

  /* Compilation, instantiation and the run all happen in `executeWasm`, which
   * also yields the artifact event. The compiled module comes back through
   * `onCompiled` so the next run in this tab skips the network and the
   * compile. */
  yield* executeWasm({
    bytes,
    name: sample.wasm,
    argv0: sample.path,
    isCancelled: () => cancelled,
    onCompiled: (module_) => {
      recorded[sample.id] = { module: module_, bytes };
    },
  });
}
