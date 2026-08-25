#!/usr/bin/env node
// A stand in for the compile service, for developing and proving the engine
// before the real one answers.
//
//     node scripts/compile-stub.mjs --port 8787 [--mode <name>]
//
// It is NOT a compiler and it never pretends to be one. It serves the wire
// contract in doc/website/PLAYGROUND-SERVICE.md and nothing else, so the engine
// can be driven through every branch it has: accepted, refused with
// diagnostics, killed on a timeout, refused by the service, and unreachable.
// The wasm it hands back for an accepted compile is a RECORDED module out of
// site/records/wasm, because a real module is the only way to prove that the
// engine's digest check, its instantiation and its output handling work on the
// path a service will actually use. The stub says so in its own compiler
// version string, so a run driven by it can never be mistaken for a run of
// something this stub compiled.
//
// Modes, selected by `--mode` or per request by an `x-stub-mode` header, so one
// running stub can serve a whole conformance sweep:
//
//   ok            200, ok true, a recorded module, empty diagnostics
//   warn          200, ok true, a module plus a warning diagnostic
//   reject        200, ok false, two diagnostics, no module
//   timeout       200, ok false, error.code timeout, no diagnostics
//   too-large     413, error.code too_large
//   unsupported   400, error.code unsupported_want
//   rate-limited  429, error.code rate_limited, Retry-After
//   internal      500, error.code internal
//   corrupt       200, ok true, a module whose declared sha256 does not match
//   truncated     200, ok true, a module with its last byte removed
//   silent        the socket is closed with no reply
//   slow          the reply is delayed past any patience the caller has

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const records = resolve(here, "..", "records", "wasm");
const manifest = JSON.parse(
  readFileSync(resolve(records, "manifest.json"), "utf8"),
);

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const at = args.indexOf(`--${name}`);
  return at >= 0 && args[at + 1] ? args[at + 1] : fallback;
};

const PORT = Number(flag("port", "8787"));
const DEFAULT_MODE = flag("mode", "ok");

const COMPILER = {
  version: "stub, not a compiler: serves recorded modules over the real wire",
  commit: manifest.recorded.commit,
  target: "wasm32-wasi",
};

const HEALTH = {
  ok: true,
  compiler: COMPILER,
  limits: { max_source_bytes: 65536, max_files: 8, compile_timeout_ms: 15000 },
  // Discovery, so the page offers only what the other end answers. `lex-silent`
  // drops lex from this array, which is how the page's plain ink fallback gets
  // exercised without pretending the service is down.
  wants: ["run", "format", "lex"],
  sandbox:
    "this is a stub and it compiles nothing, so there is nothing to contain",
};

// The diagnostics are real: they are the recorded compiler output this
// repository already carries, so the stub cannot invent a message shape the
// compiler would never print.
const recorded = JSON.parse(
  readFileSync(resolve(here, "..", "records", "diagnostics.json"), "utf8"),
);

// Same principle for lexing. A stub cannot lex, so it serves the recorded
// output of the compiler's own highlighter over exactly the files it was
// recorded from. The page strips the spans and refuses to paint unless the
// recovered text is byte identical to what it sent, so a synthetic stream
// would fail that check and prove nothing about the live path. A recording
// passes it for a real reason.
const highlight = JSON.parse(
  readFileSync(resolve(here, "..", "records", "highlight.json"), "utf8"),
);

/** The characters a recorded listing's markup encodes. */
function recoveredText(html) {
  return html
    .replace(/<[^>]+>/g, "")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&amp;", "&");
}

/** Recorded listings by the text they encode, so a submission can be matched. */
const listingsByText = new Map(
  Object.values(highlight.files ?? {}).map((html) => [recoveredText(html), html]),
);

function diagnosticFrom(entry) {
  const found = /^In (.+):(\d+):(\d+)\s*$/m.exec(entry.stderr);
  return {
    severity: "error",
    path: found ? found[1] : null,
    line: found ? Number(found[2]) : null,
    column: found ? Number(found[3]) : null,
    message: entry.title,
    rule: entry.rule ?? null,
    raw: entry.stderr,
  };
}

function moduleFor(entry, mode) {
  const sample =
    manifest.samples.find((one) => one.id === entry) ?? manifest.samples[0];
  const whole = readFileSync(resolve(records, sample.wasm));

  /* `truncated` models a proxy that cut the body short: the service declared
   * the digest of what it compiled, and fewer bytes arrived. So the hash is
   * taken BEFORE the truncation, which is what makes this a test of the
   * engine's digest check rather than a test of the wasm parser. Hashing after
   * the cut, which is what this did first, produced a body that agreed with
   * itself and proved nothing. */
  const bytes = mode === "truncated" ? whole.subarray(0, whole.length - 1) : whole;
  const declared =
    mode === "corrupt"
      ? "0".repeat(64)
      : createHash("sha256").update(whole).digest("hex");

  return {
    wasm_base64: bytes.toString("base64"),
    bytes: whole.length,
    sha256: declared,
  };
}

const cors = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "content-type, x-stub-mode",
  "access-control-allow-methods": "GET, POST, OPTIONS",
};

function send(res, status, body, extra = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(text),
    ...cors,
    ...extra,
  });
  res.end(text);
}

const server = createServer((req, res) => {
  const mode = req.headers["x-stub-mode"] ?? DEFAULT_MODE;

  if (req.method === "OPTIONS") {
    res.writeHead(204, cors);
    res.end();
    return;
  }

  if (req.url.startsWith("/v1/health")) {
    if (mode === "silent") {
      req.socket.destroy();
      return;
    }
    /* `lex-silent` is a service that simply does not offer lexing. The page
     * must then never ask, and must fall back to plain ink without saying
     * anything to the visitor, which is a different case from a service that
     * offers lex and then refuses one request. */
    const wants =
      mode === "lex-silent"
        ? HEALTH.wants.filter((want) => want !== "lex")
        : HEALTH.wants;
    send(res, 200, { ...HEALTH, wants });
    return;
  }

  if (req.url.startsWith("/v1/lex")) {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      let request;
      try {
        request = JSON.parse(raw);
      } catch {
        send(res, 400, {
          error: { code: "bad_request", message: "body is not json" },
        });
        return;
      }

      const text = request.files?.[0]?.text ?? "";

      /* `lex-lies` returns markup that does not encode the submitted text.
       * There is exactly one honest response to that on the page, which is to
       * refuse to paint and fall back to plain ink, because painting one
       * program's tokens over another program's characters is the silently
       * wrong listing this whole pipeline exists to prevent. */
      if (mode === "lex-lies") {
        send(res, 200, {
          ok: true,
          html: '<span class="k">module</span> <span class="m">somethingelse</span>\n',
        });
        return;
      }

      const listing = listingsByText.get(text);
      if (listing === undefined) {
        send(res, 200, {
          ok: false,
          error: {
            code: "unsupported_want",
            message: "this stub has no lexer, only recordings",
          },
        });
        return;
      }
      send(res, 200, { ok: true, html: listing });
    });
    return;
  }

  if (!req.url.startsWith("/v1/compile")) {
    send(res, 404, { error: { code: "bad_request", message: "no such path" } });
    return;
  }

  let raw = "";
  req.on("data", (chunk) => {
    raw += chunk;
  });
  req.on("end", () => {
    let request;
    try {
      request = JSON.parse(raw);
    } catch {
      send(res, 400, {
        error: { code: "bad_request", message: "body is not json" },
      });
      return;
    }

    const entry = String(request.entry ?? "").replace(/^.*\//, "").replace(/\.iyi$/, "");
    const answer = (status, body, extra) => send(res, status, body, extra);

    switch (mode) {
      case "silent":
        req.socket.destroy();
        return;
      case "slow":
        setTimeout(() => answer(200, { ok: true, want: request.want, diagnostics: [], module: moduleFor(entry, mode), stderr: "", compiler: COMPILER, compile_ms: 60000 }), 120000);
        return;
      case "reject":
        answer(200, {
          ok: false,
          want: request.want,
          diagnostics: recorded.cases.slice(0, 2).map(diagnosticFrom),
          stderr: recorded.cases[0].stderr,
          compiler: COMPILER,
          compile_ms: 412,
        });
        return;
      case "timeout":
        answer(200, {
          ok: false,
          want: request.want,
          diagnostics: [],
          error: {
            code: "timeout",
            message: "the compiler was still running after 15000 ms",
          },
          compiler: COMPILER,
          compile_ms: 15000,
        });
        return;
      case "too-large":
        answer(413, {
          error: {
            code: "too_large",
            message: "source is larger than this service accepts",
            limit_bytes: 65536,
          },
        });
        return;
      case "unsupported":
        answer(400, {
          error: {
            code: "unsupported_want",
            message: `this service implements run and format, not ${request.want}`,
          },
        });
        return;
      case "rate-limited":
        answer(
          429,
          {
            error: {
              code: "rate_limited",
              message: "too many compiles from this address",
              retry_after_seconds: 30,
            },
          },
          { "retry-after": "30" },
        );
        return;
      case "internal":
        answer(500, {
          error: { code: "internal", message: "the compile host is not well" },
        });
        return;
      case "warn":
        answer(200, {
          ok: true,
          want: request.want,
          diagnostics: [
            { ...diagnosticFrom(recorded.cases[0]), severity: "warning" },
          ],
          module: moduleFor(entry, mode),
          stderr: "",
          compiler: COMPILER,
          compile_ms: 733,
        });
        return;
      default:
        answer(200, {
          ok: true,
          want: request.want,
          diagnostics: [],
          module: moduleFor(entry, mode),
          stderr: "",
          compiler: COMPILER,
          compile_ms: 604,
        });
    }
  });
});

server.listen(PORT, () => {
  console.log(
    `compile stub on http://127.0.0.1:${PORT}, default mode ${DEFAULT_MODE}, ` +
      `serving recorded modules from site/records/wasm`,
  );
});
