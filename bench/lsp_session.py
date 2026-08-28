#!/usr/bin/env python3
"""Drives `iyi lsp` through one scripted editing session and asserts on
every answer. This is the gate for SPEC.md III.8 #2: each claim the
release makes about the server is a step here, and a step that fails
names itself and exits 1.

The session is a person's first five minutes, plus the agent's first
question:
  1. initialize        -> the server names itself and its capabilities
  2. didOpen broken    -> diagnostics arrive, on the right line, citing SPEC
  3. didChange fixed   -> diagnostics empty (and the round trip is timed)
  4. hover             -> the variable's type
  5. definition        -> jumps into the sibling module, unsaved-buffer aware
  6. documentSymbol    -> the outline, nested
  7. iyi/contextPack   -> the import's surface as data, from the buffer
"""

import json
import os
import subprocess
import sys
import tempfile
import time

IYI = os.environ.get("IYI", "./bin/iyi")


class Client:
    def __init__(self):
        self.proc = subprocess.Popen(
            [IYI, "lsp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self.next_id = 0

    def send(self, method, params, wait=True):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "method": method, "params": params}
        if wait:
            message["id"] = self.next_id
        body = json.dumps(message).encode()
        self.proc.stdin.write(
            b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        self.proc.stdin.flush()
        if wait:
            return self.wait_for(lambda m: m.get("id") == self.next_id)
        return None

    def read_message(self):
        length = None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise SystemExit("server closed the pipe")
            line = line.strip()
            if not line:
                break
            if line.startswith(b"Content-Length:"):
                length = int(line.split(b":")[1])
        return json.loads(self.proc.stdout.read(length))

    def wait_for(self, predicate):
        while True:
            message = self.read_message()
            if predicate(message):
                return message

    def diagnostics(self, uri=None):
        return self.wait_for(
            lambda m: m.get("method") == "textDocument/publishDiagnostics"
            and (uri is None or m["params"]["uri"] == uri)
        )["params"]


def step(n, name, ok, detail=""):
    mark = "ok" if ok else "FAIL"
    print(f"step {n:2} {name}: {mark}  {detail}")
    if not ok:
        sys.exit(1)


def main():
    work = tempfile.mkdtemp(prefix="iyi-lsp-gate")
    lib = os.path.join(work, "greet.iyi")
    app = os.path.join(work, "app.iyi")
    with open(lib, "w") as f:
        f.write('module greet\n\npub def shout(name : String) : String\n'
                '  name.upcase\nend\n')
    with open(app, "w") as f:
        f.write("module app\n")
    app_uri = "file://" + app

    c = Client()

    # 1. initialize
    reply = c.send("initialize", {"rootUri": "file://" + work,
                                  "capabilities": {}})
    caps = reply["result"]["capabilities"]
    step(1, "initialize", reply["result"]["serverInfo"]["name"] == "iyi"
         and caps["hoverProvider"] and caps["definitionProvider"]
         and caps["documentSymbolProvider"],
         f"server {reply['result']['serverInfo']['version']}")
    c.send("initialized", {}, wait=False)

    # 2. didOpen a file whose call mis-types the argument. The def is only
    #    typed when called, so the fixture calls it.
    broken = ("module app\n\nimport greet\nusing greet::{shout}\n\n"
              "def run : String\n  shout(42)\nend\n\nputs run\n")
    c.send("textDocument/didOpen",
           {"textDocument": {"uri": app_uri, "languageId": "iyi",
                             "version": 1, "text": broken}}, wait=False)
    diags = c.diagnostics()["diagnostics"]
    step(2, "didOpen broken -> diagnostics",
         len(diags) == 1 and diags[0]["range"]["start"]["line"] == 6,
         f"line {diags[0]['range']['start']['line'] + 1}: "
         f"{diags[0]['message'].splitlines()[0][:60]}")

    # 3. didChange to a SPEC-citing error (`!` on a union with no error
    #    member is refused and the message names its section), then fixed.
    speccy = ("module app\n\nimport greet\nusing greet::{shout}\n\n"
              "def run : String\n  shout(\"iyi\")!\nend\n\nputs run\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 2},
            "contentChanges": [{"text": speccy}]}, wait=False)
    diags = c.diagnostics()["diagnostics"]
    cites = diags and diags[0].get("code", "").startswith("SPEC")
    step(3, "error cites its SPEC section as data", bool(cites),
         f"code {diags[0].get('code')!r}, "
         f"link {'yes' if diags[0].get('codeDescription') else 'no'}")

    fixed = ("module app\n\nimport greet\nusing greet::{shout}\n\n"
             "def run : String\n  shout(\"iyi\")\nend\n\nputs run\n")
    started = time.monotonic()
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 3},
            "contentChanges": [{"text": fixed}]}, wait=False)
    diags = c.diagnostics()["diagnostics"]
    elapsed = time.monotonic() - started
    step(4, "didChange fixed -> clean", diags == [],
         f"keystroke to verdict {elapsed * 1000:.0f} ms")
    if elapsed > 5.0:
        step(4, "keystroke latency bound", False, f"{elapsed:.2f}s > 5s")

    # 5. hover on a local whose type came through the import.
    hovered = ("module app\n\nimport greet\nusing greet::{shout}\n\n"
               "def run : String\n  loud = shout(\"iyi\")\n"
               "  loud\nend\n\nputs run\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 4},
            "contentChanges": [{"text": hovered}]}, wait=False)
    c.diagnostics()
    reply = c.send("textDocument/hover",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 7, "character": 3}})
    value = (reply["result"] or {}).get("contents", {}).get("value", "")
    step(5, "hover names the type", "loud : String" in value,
         value.replace("\n", " "))

    # 6. definition on the call jumps into the sibling module's def.
    reply = c.send("textDocument/definition",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 6, "character": 11}})
    locs = reply["result"] or []
    step(6, "definition jumps to the import",
         any(l["uri"].endswith("greet.iyi") and
             l["range"]["start"]["line"] == 2 for l in locs),
         f"{len(locs)} location(s), first {locs and locs[0]['uri']}")

    # 7. documentSymbol: the outline — the header's module at the root,
    #    the def nested inside it.
    reply = c.send("textDocument/documentSymbol",
                   {"textDocument": {"uri": app_uri}})

    def flatten(symbols):
        for s in symbols:
            yield s["name"]
            yield from flatten(s.get("children", []))

    names = list(flatten(reply["result"]))
    step(7, "documentSymbol lists the outline",
         "App" in names and "run" in names, f"symbols {names}")

    # 8. iyi/contextPack: the agent's question, answered from the buffer.
    reply = c.send("iyi/contextPack", {"textDocument": {"uri": app_uri}})
    result = reply["result"]
    pack = json.loads(result["output"]) if result["ok"] else {}
    surfaces = [i for i in pack.get("imports", []) if i.get("api")]
    step(8, "iyi/contextPack grounds the buffer",
         result["ok"] and len(surfaces) == 1 and
         surfaces[0]["import"] == "greet",
         f"{len(surfaces)} surface(s), interface_hash "
         f"{surfaces[0]['api'].get('interface_hash', '')[:12]}")

    # 9. the unsaved sibling: rename greet's def in its *buffer* only,
    #    follow the rename in app. The verdict is clean because the
    #    import reads the buffer, not the disk — and the disk still says
    #    `shout`, which is the whole claim.
    greet_uri = "file://" + lib
    with open(lib) as f:
        greet_text = f.read()
    c.send("textDocument/didOpen",
           {"textDocument": {"uri": greet_uri, "languageId": "iyi",
                             "version": 1, "text": greet_text}}, wait=False)
    c.diagnostics(greet_uri)
    c.send("textDocument/didChange",
           {"textDocument": {"uri": greet_uri, "version": 2},
            "contentChanges": [{"text": greet_text.replace("shout",
                                                           "holler")}]},
           wait=False)
    c.diagnostics(greet_uri)
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 5},
            "contentChanges": [{"text": hovered.replace("shout",
                                                        "holler")}]},
           wait=False)
    diags = c.diagnostics(app_uri)["diagnostics"]
    with open(lib) as f:
        disk_still = "shout" in f.read()
    step(9, "unsaved sibling is seen through the import",
         diags == [] and disk_still,
         "buffer renamed shout->holler, disk untouched, verdict clean")

    # 10. a nested module opened on its own: `parser.iyi` lives under
    #     calc/, its header says so, and its import names the sibling
    #     from the root. The root is derived from the header (IV.6 read
    #     backwards), so the verdict is clean — the way a build from the
    #     root would see it, without one.
    calc = os.path.join(work, "calc")
    os.makedirs(calc)
    with open(os.path.join(calc, "lexer.iyi"), "w") as f:
        f.write("module calc/lexer\n\npub def token : String\n"
                '  "NUM"\nend\n')
    parser_path = os.path.join(calc, "parser.iyi")
    parser_text = ("module calc/parser\n\nimport calc/lexer\n"
                   "using calc/lexer::{token}\n\n"
                   "pub def first : String\n  token\nend\n\nputs first\n")
    with open(parser_path, "w") as f:
        f.write(parser_text)
    parser_uri = "file://" + parser_path
    c.send("textDocument/didOpen",
           {"textDocument": {"uri": parser_uri, "languageId": "iyi",
                             "version": 1, "text": parser_text}}, wait=False)
    diags = c.diagnostics(parser_uri)["diagnostics"]
    step(10, "nested module resolves from its header's root", diags == [],
         "calc/parser.iyi imports calc/lexer, opened alone, clean")

    # 11. completion after a dot: the buffer stops compiling the moment
    #     the dot lands, which is exactly when completion fires — so the
    #     answer comes from the last result that held together.
    holler_app = hovered.replace("shout", "holler")
    dotted = holler_app.replace("\n  loud\n", "\n  loud.up\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 6},
            "contentChanges": [{"text": dotted}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 7, "character": 9}})
    items = reply["result"]["items"]
    labels = [i["label"] for i in items]
    upcase = next((i for i in items if i["label"] == "upcase"), None)
    step(11, "completion after a dot lists the receiver's methods",
         upcase is not None and all(l.startswith("up") for l in labels),
         f"{len(labels)} item(s) for 'loud.up', "
         f"upcase detail {upcase and upcase['detail']!r}")

    # 12. bare completion: the scope's own names, typed.
    bare = holler_app.replace("\n  loud\n", "\n  lo\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 7},
            "contentChanges": [{"text": bare}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 7, "character": 4}})
    items = reply["result"]["items"]
    loud = next((i for i in items if i["label"] == "loud"), None)
    step(12, "bare completion offers the scope, typed",
         loud is not None and loud["kind"] == 6 and
         loud["detail"] == "String",
         f"loud : {loud and loud['detail']}")

    # 13. references, asked at the *def*: under R-1 the callers live in
    #     the consumers' compiles, so the session answers from every open
    #     document — the call in app.iyi, the `using` selection that
    #     brings the name in (the gate's own find: miss it and a rename
    #     leaves a program that does not compile), and the declaration.
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 8},
            "contentChanges": [{"text": holler_app}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/references",
                   {"textDocument": {"uri": greet_uri},
                    "position": {"line": 2, "character": 9},
                    "context": {"includeDeclaration": True}})
    locs = reply["result"] or []
    names = sorted({l["uri"].rsplit("/", 1)[-1] for l in locs})
    app_lines = sorted(l["range"]["start"]["line"] for l in locs
                       if l["uri"].endswith("app.iyi"))
    step(13, "references cross the module boundary, using line included",
         names == ["app.iyi", "greet.iyi"] and len(locs) == 3 and
         app_lines == [3, 6],
         f"{len(locs)} site(s): call, using selection, declaration")

    # 14. rename off the typed graph: one request, two files edited —
    #     then both buffers change to the edit and the verdicts are clean.
    reply = c.send("textDocument/rename",
                   {"textDocument": {"uri": greet_uri},
                    "position": {"line": 2, "character": 9},
                    "newName": "yell"})
    changes = reply["result"]["changes"]
    edit_count = sum(len(e) for e in changes.values())
    texts = {app_uri: holler_app,
             greet_uri: greet_text.replace("shout", "holler")}
    for uri, edits in changes.items():
        lines = texts[uri].split("\n")
        for e in sorted(edits, key=lambda e: -e["range"]["start"]["character"]):
            l = e["range"]["start"]["line"]
            s, t = e["range"]["start"]["character"], e["range"]["end"]["character"]
            lines[l] = lines[l][:s] + e["newText"] + lines[l][t:]
        texts[uri] = "\n".join(lines)
    clean = True
    for version, uri in ((3, greet_uri), (9, app_uri)):
        c.send("textDocument/didChange",
               {"textDocument": {"uri": uri, "version": version},
                "contentChanges": [{"text": texts[uri]}]}, wait=False)
        clean = clean and c.diagnostics(uri)["diagnostics"] == []
    step(14, "rename edits both files, using line too, both stay clean",
         len(changes) == 2 and edit_count == 3 and
         "using greet::{yell}" in texts[app_uri] and
         "def yell" in texts[greet_uri] and clean,
         f"{edit_count} edit(s) across {len(changes)} file(s)")

    # 15. shutdown/exit: the server leaves when told, not before.
    c.send("shutdown", {})
    c.send("exit", {}, wait=False)
    step(15, "shutdown then exit", c.proc.wait(timeout=10) == 0)

    print("lsp gate: every step held")


if __name__ == "__main__":
    main()
