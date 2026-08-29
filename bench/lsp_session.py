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

Then the everyday half a person meets in the first hour: incremental
range edits, the did-you-mean quickfix, signature help mid-call,
document highlight, folding, workspace symbols, prepareRename,
semantic tokens, inlay hints, type definition, and formatting.
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

    def request_nowait(self, method, params):
        """A request whose answer is read later — how a cancel gets to
        overtake it."""
        self.next_id += 1
        message = {"jsonrpc": "2.0", "method": method, "params": params,
                   "id": self.next_id}
        body = json.dumps(message).encode()
        self.proc.stdin.write(
            b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        self.proc.stdin.flush()
        return self.next_id

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
                                  "capabilities": {"textDocument": {
                                      "completion": {"completionItem": {
                                          "snippetSupport": True}}}}})
    caps = reply["result"]["capabilities"]
    step(1, "initialize", reply["result"]["serverInfo"]["name"] == "iyi"
         and caps["hoverProvider"] and caps["definitionProvider"]
         and caps["documentSymbolProvider"]
         and caps["textDocumentSync"]["change"] == 2
         and caps["signatureHelpProvider"]
         and caps["documentFormattingProvider"]
         and caps["documentHighlightProvider"]
         and caps["foldingRangeProvider"]
         and caps["workspaceSymbolProvider"]
         and caps["inlayHintProvider"]
         and caps["typeDefinitionProvider"]
         and caps["renameProvider"]["prepareProvider"]
         and caps["codeActionProvider"]["codeActionKinds"] == ["quickfix"]
         and caps["semanticTokensProvider"]["legend"]["tokenTypes"]
         and caps["implementationProvider"]
         and caps["callHierarchyProvider"]
         and caps["selectionRangeProvider"]
         and caps["diagnosticProvider"]["workspaceDiagnostics"]
         and caps["typeHierarchyProvider"]
         and caps["documentLinkProvider"] is not None
         and caps["codeLensProvider"] is not None
         and caps["executeCommandProvider"]["commands"] == ["iyi.run"]
         and caps["semanticTokensProvider"]["full"]["delta"],
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
                '  "NUM"\nend\n\npub def glyph : String\n  "+"\nend\n')
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

    # 15. incremental didChange: a range edit in wire units, not a full
    #     text — the server applies it, breaks, then a second range edit
    #     heals it.
    app_text = texts[app_uri]
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 10},
            "contentChanges": [{
                "range": {"start": {"line": 6, "character": 9},
                          "end": {"line": 6, "character": 13}},
                "text": "yel"}]}, wait=False)
    diags = c.diagnostics(app_uri)["diagnostics"]
    broke = len(diags) == 1 and diags[0]["range"]["start"]["line"] == 6
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 11},
            "contentChanges": [{
                "range": {"start": {"line": 6, "character": 9},
                          "end": {"line": 6, "character": 12}},
                "text": "yell"}]}, wait=False)
    healed = c.diagnostics(app_uri)["diagnostics"] == []
    step(15, "incremental sync: range edits apply", broke and healed,
         "yell -> yel broke line 7, a range edit back healed it")

    # 16. codeAction: the compiler's own "Did you mean", made clickable.
    typo = app_text.replace("\n  loud\n", "\n  loud.upcas\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 12},
            "contentChanges": [{"text": typo}]}, wait=False)
    diags = c.diagnostics(app_uri)["diagnostics"]
    reply = c.send("textDocument/codeAction",
                   {"textDocument": {"uri": app_uri},
                    "range": diags[0]["range"] if diags else
                    {"start": {"line": 7, "character": 0},
                     "end": {"line": 7, "character": 0}},
                    "context": {"diagnostics": diags}})
    actions = reply["result"] or []
    fix = next((a for a in actions
                if a["title"] == "Change to 'upcase'"), None)
    applied = ""
    if fix:
        lines = typo.split("\n")
        for uri, edits in fix["edit"]["changes"].items():
            for e in edits:
                l = e["range"]["start"]["line"]
                s = e["range"]["start"]["character"]
                t = e["range"]["end"]["character"]
                lines[l] = lines[l][:s] + e["newText"] + lines[l][t:]
        applied = "\n".join(lines)
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 13},
            "contentChanges": [{"text": applied or typo}]}, wait=False)
    clean = c.diagnostics(app_uri)["diagnostics"] == []
    step(16, "codeAction turns did-you-mean into a quickfix",
         fix is not None and "loud.upcase" in applied and clean,
         f"{len(actions)} action(s), quickfix applied and clean")

    # 17. signatureHelp, asked right after the `(` lands — the buffer
    #     has no syntax there; the overload comes off the typed graph.
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 14},
            "contentChanges": [{"text": app_text}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/signatureHelp",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 6, "character": 14}})
    result = reply["result"] or {}
    sigs = result.get("signatures", [])
    label = sigs[0]["label"] if sigs else ""
    step(17, "signatureHelp names the overload mid-call",
         label.startswith("yell(") and "String" in label and
         result.get("activeParameter") == 0,
         f"label {label!r}")

    # 18. documentHighlight on the def: the declaration is the write,
    #     the call is the read, both in this buffer alone.
    reply = c.send("textDocument/documentHighlight",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 5, "character": 5}})
    highlights = reply["result"] or []
    kinds = sorted(h["kind"] for h in highlights)
    hl_lines = sorted(h["range"]["start"]["line"] for h in highlights)
    step(18, "documentHighlight marks def and call",
         kinds == [2, 3] and hl_lines == [5, 10],
         f"{len(highlights)} range(s) at lines {hl_lines}")

    # 19. foldingRange: the def folds off the outline, the import
    #     header off the text.
    reply = c.send("textDocument/foldingRange",
                   {"textDocument": {"uri": app_uri}})
    folds = reply["result"] or []
    has_def = any(f["startLine"] == 5 and f["endLine"] == 8 for f in folds)
    has_imports = any(f.get("kind") == "imports" and f["startLine"] == 2
                      and f["endLine"] == 3 for f in folds)
    step(19, "foldingRange folds the def and the import header",
         has_def and has_imports, f"{len(folds)} fold(s)")

    # 20. workspace/symbol: the open buffer wins over the disk — the
    #     disk still says shout, the buffer says yell, yell is found.
    reply = c.send("workspace/symbol", {"query": "yell"})
    syms = reply["result"] or []
    hit = next((s for s in syms if s["name"] == "yell"
                and s["location"]["uri"].endswith("greet.iyi")), None)
    step(20, "workspace/symbol finds the def across the project",
         hit is not None, f"{len(syms)} symbol(s)")

    # 21. prepareRename: the range and placeholder before the input box.
    reply = c.send("textDocument/prepareRename",
                   {"textDocument": {"uri": greet_uri},
                    "position": {"line": 2, "character": 9}})
    result = reply["result"] or {}
    step(21, "prepareRename names the range and placeholder",
         result.get("placeholder") == "yell" and
         result["range"]["start"]["character"] == 8 and
         result["range"]["end"]["character"] == 12,
         f"placeholder {result.get('placeholder')!r}")

    # 22. semanticTokens: the lexer colors the buffer — keyword, def
    #     name, type, string — with no grammar installed anywhere.
    reply = c.send("textDocument/semanticTokens/full",
                   {"textDocument": {"uri": app_uri}})
    data = (reply["result"] or {}).get("data", [])
    decoded = []
    line = 0
    start = 0
    for i in range(0, len(data), 5):
        dl, ds, ln, tt, _ = data[i:i + 5]
        line += dl
        start = start + ds if dl == 0 else ds
        decoded.append((line, start, ln, tt))
    # legend: 0 keyword, 1 string, 4 type, 5 function, 6 variable
    has_def_kw = (5, 0, 3, 0) in decoded
    has_fn = (5, 4, 3, 5) in decoded
    has_str = any(l == 6 and tt == 1 for (l, s, ln, tt) in decoded)
    has_type = any(l == 5 and tt == 4 for (l, s, ln, tt) in decoded)
    has_var = (6, 2, 4, 6) in decoded       # `loud`, a variable
    has_call = (6, 9, 4, 5) in decoded      # `yell(`, a call
    step(22, "semanticTokens color the buffer with no grammar",
         has_def_kw and has_fn and has_str and has_type and
         has_var and has_call,
         f"{len(decoded)} token(s)")

    # 23. inlayHint: the inferred type after the assignment, the
    #     parameter's name before the bare literal.
    reply = c.send("textDocument/inlayHint",
                   {"textDocument": {"uri": app_uri},
                    "range": {"start": {"line": 0, "character": 0},
                              "end": {"line": 11, "character": 0}}})
    hints = reply["result"] or []
    type_hint = next((h for h in hints if h["label"] == ": String"
                      and h["position"]["line"] == 6), None)
    param_hint = next((h for h in hints if h["label"] == "name:"), None)
    step(23, "inlayHint shows inferred type and parameter name",
         type_hint is not None and param_hint is not None and
         param_hint["position"] == {"line": 6, "character": 14},
         f"{len(hints)} hint(s): {[h['label'] for h in hints]}")

    # 24. typeDefinition: from the local to where String is declared.
    reply = c.send("textDocument/typeDefinition",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 7, "character": 3}})
    locs = reply["result"] or []
    step(24, "typeDefinition jumps to the type's declaration",
         len(locs) >= 1,
         f"{len(locs)} location(s), first {locs and locs[0]['uri']}")

    # 25. formatting: the formatter, in process, one whole-document edit.
    sloppy = app_text.replace('yell("iyi")', 'yell(  "iyi" )')
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 15},
            "contentChanges": [{"text": sloppy}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/formatting",
                   {"textDocument": {"uri": app_uri},
                    "options": {"tabSize": 2, "insertSpaces": True}})
    edits = reply["result"] or []
    formatted = edits[0]["newText"] if edits else ""
    step(25, "formatting is the formatter, in process",
         len(edits) == 1 and 'yell("iyi")' in formatted and
         formatted.count("\n") == sloppy.count("\n"),
         "one whole-document edit, call tightened")

    # 26. a trait, its impl, and the call graph around them — one
    #     fixture serves implementation, call hierarchy, and selection.
    shapes_path = os.path.join(work, "shapes.iyi")
    shapes_text = ("module shapes\n\n"
                   "pub trait Paint\n  abstract def paint : String\nend\n\n"
                   "pub struct Dot\nend\n\n"
                   "impl Paint for Dot\n  def paint : String\n"
                   '    "."\n  end\nend\n\n'
                   "pub def render(thing : Dot) : String\n"
                   "  thing.paint\nend\n\nputs render(Dot.new)\n")
    with open(shapes_path, "w") as f:
        f.write(shapes_text)
    shapes_uri = "file://" + shapes_path
    c.send("textDocument/didOpen",
           {"textDocument": {"uri": shapes_uri, "languageId": "iyi",
                             "version": 1, "text": shapes_text}}, wait=False)
    diags = c.diagnostics(shapes_uri)["diagnostics"]
    step(26, "the trait fixture compiles clean", diags == [],
         "shapes.iyi: trait Paint, impl for Dot, render calls paint")

    # 27. implementation: the trait name answers with its implementors.
    reply = c.send("textDocument/implementation",
                   {"textDocument": {"uri": shapes_uri},
                    "position": {"line": 2, "character": 11}})
    locs = reply["result"] or []
    step(27, "implementation jumps from the trait to its impl types",
         any(l["uri"].endswith("shapes.iyi") and
             l["range"]["start"]["line"] == 6 for l in locs),
         f"{len(locs)} implementor(s)")

    # 28. call hierarchy: prepare on the call, incoming names the
    #     enclosing def, outgoing from that def names the callee.
    reply = c.send("textDocument/prepareCallHierarchy",
                   {"textDocument": {"uri": shapes_uri},
                    "position": {"line": 16, "character": 9}})
    items = reply["result"] or []
    paint_item = items[0] if items else None
    incoming = []
    if paint_item:
        reply = c.send("callHierarchy/incomingCalls", {"item": paint_item})
        incoming = reply["result"] or []
    callers = sorted(e["from"]["name"] for e in incoming)
    reply = c.send("textDocument/prepareCallHierarchy",
                   {"textDocument": {"uri": shapes_uri},
                    "position": {"line": 15, "character": 9}})
    render_items = reply["result"] or []
    outgoing = []
    if render_items:
        reply = c.send("callHierarchy/outgoingCalls",
                       {"item": render_items[0]})
        outgoing = reply["result"] or []
    callees = sorted(e["to"]["name"] for e in outgoing)
    step(28, "call hierarchy answers both directions",
         paint_item is not None and paint_item["name"] == "paint" and
         "render" in callers and "paint" in callees,
         f"paint <- {callers}, render -> {callees}")

    # 29. selectionRange: expand from inside the string literal, out
    #     through the def, to the file — strictly nested.
    reply = c.send("textDocument/selectionRange",
                   {"textDocument": {"uri": shapes_uri},
                    "positions": [{"line": 11, "character": 5}]})
    chain = (reply["result"] or [None])[0] or {}
    depth = 0
    node = chain
    nested = True
    while node:
        depth += 1
        parent = node.get("parent")
        if parent:
            inner, outer = node["range"], parent["range"]
            nested = nested and (
                (outer["start"]["line"], outer["start"]["character"]) <=
                (inner["start"]["line"], inner["start"]["character"]) and
                (inner["end"]["line"], inner["end"]["character"]) <=
                (outer["end"]["line"], outer["end"]["character"]))
        node = parent
    step(29, "selectionRange expands strictly outward",
         depth >= 3 and nested and
         chain.get("range", {}).get("start", {}).get("line") == 11,
         f"{depth} nested range(s)")

    # 30. pull diagnostics: the agent's shape — ask, don't subscribe.
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 16},
            "contentChanges": [{"text": sloppy.replace("yell(", "yel(")}]},
           wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/diagnostic",
                   {"textDocument": {"uri": app_uri}})
    pulled = reply["result"]
    broke = pulled["kind"] == "full" and len(pulled["items"]) == 1
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 17},
            "contentChanges": [{"text": app_text}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/diagnostic",
                   {"textDocument": {"uri": app_uri}})
    healed = reply["result"]["items"] == []
    step(30, "pull diagnostics answer on request", broke and healed,
         "broken pulled 1 item, fixed pulled none")

    # 31. workspace diagnostics: the whole project's verdict in one
    #     request — a file nobody opened is still judged, R-1 makes
    #     every module its own cheap compile.
    with open(os.path.join(work, "broken.iyi"), "w") as f:
        f.write("module broken\n\ndef boom : String\n  1\nend\n\nputs boom\n")
    reply = c.send("workspace/diagnostic", {})
    items = reply["result"]["items"]
    dirty = [i for i in items if i["items"]]
    step(31, "workspace diagnostics judge the whole project",
         len(dirty) == 1 and dirty[0]["uri"].endswith("broken.iyi") and
         any(i["uri"].endswith("shapes.iyi") for i in items),
         f"{len(items)} file(s) judged, {len(dirty)} dirty")

    # 32. references reach a file nobody opened: printer.iyi calls
    #     `token` from the disk, and the workspace walk finds it beside
    #     the open buffer's call — the gap gopls' index covers, closed
    #     without one.
    printer_path = os.path.join(calc, "printer.iyi")
    printer_text = ("module calc/printer\n\nimport calc/lexer\n"
                    "using calc/lexer::{token}\n\n"
                    "pub def show : String\n  token\nend\n\nputs show\n")
    with open(printer_path, "w") as f:
        f.write(printer_text)
    lexer_uri = "file://" + os.path.join(calc, "lexer.iyi")
    reply = c.send("textDocument/references",
                   {"textDocument": {"uri": lexer_uri},
                    "position": {"line": 2, "character": 9},
                    "context": {"includeDeclaration": False}})
    locs = reply["result"] or []
    files = sorted({l["uri"].rsplit("/", 1)[-1] for l in locs})
    step(32, "references reach files nobody opened",
         "printer.iyi" in files and "parser.iyi" in files,
         f"{len(locs)} site(s) across {files}")

    # 33. rename follows: one request edits the declaration, the open
    #     consumer, and the consumer on disk — miss the last and the
    #     rename ships a program that does not compile.
    reply = c.send("textDocument/rename",
                   {"textDocument": {"uri": lexer_uri},
                    "position": {"line": 2, "character": 9},
                    "newName": "lex"})
    changes = reply["result"]["changes"]
    changed = sorted(u.rsplit("/", 1)[-1] for u in changes)
    step(33, "rename edits the unopened consumer too",
         changed == ["lexer.iyi", "parser.iyi", "printer.iyi"],
         f"{sum(len(e) for e in changes.values())} edit(s) across {changed}")

    # 34. incoming calls cross the same boundary: the def in lexer.iyi
    #     is called by defs in both consumers, one of them never opened.
    reply = c.send("textDocument/prepareCallHierarchy",
                   {"textDocument": {"uri": lexer_uri},
                    "position": {"line": 2, "character": 9}})
    items = reply["result"] or []
    incoming = []
    if items:
        reply = c.send("callHierarchy/incomingCalls", {"item": items[0]})
        incoming = reply["result"] or []
    callers = sorted(e["from"]["name"] for e in incoming)
    step(34, "incoming calls name the unopened caller",
         "first" in callers and "show" in callers,
         f"token <- {callers}")

    # 35. auto-import completion: a fresh buffer that has never
    #     compiled types `tok`; the workspace's exports answer anyway
    #     (R-2 made `pub` a parse-time fact), and the item carries the
    #     `import`/`using` pair as additionalTextEdits.
    scratch_path = os.path.join(work, "scratch.iyi")
    scratch_text = ("module scratch\n\ndef go : String\n  tok\nend\n\n"
                    "puts go\n")
    scratch_uri = "file://" + scratch_path
    with open(scratch_path, "w") as f:
        f.write(scratch_text)
    c.send("textDocument/didOpen",
           {"textDocument": {"uri": scratch_uri, "languageId": "iyi",
                             "version": 1, "text": scratch_text}}, wait=False)
    c.diagnostics(scratch_uri)
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": scratch_uri},
                    "position": {"line": 3, "character": 5}})
    items = reply["result"]["items"]
    token_item = next((i for i in items if i["label"] == "token"), None)
    edited = scratch_text
    if token_item:
        lines = edited.split("\n")
        lines[3] = "  token"
        for e in sorted(token_item.get("additionalTextEdits", []),
                        key=lambda e: -e["range"]["start"]["line"]):
            l = e["range"]["start"]["line"]
            s = e["range"]["start"]["character"]
            t = e["range"]["end"]["character"]
            if s == t == 0 and e["newText"].endswith("\n"):
                lines[l:l] = e["newText"].split("\n")[:-1]
            else:
                lines[l] = lines[l][:s] + e["newText"] + lines[l][t:]
        edited = "\n".join(lines)
    c.send("textDocument/didChange",
           {"textDocument": {"uri": scratch_uri, "version": 2},
            "contentChanges": [{"text": edited}]}, wait=False)
    clean = c.diagnostics(scratch_uri)["diagnostics"] == []
    step(35, "completion auto-imports across the workspace",
         token_item is not None and
         token_item["labelDetails"]["description"] == "calc/lexer" and
         "import calc/lexer" in edited and
         "using calc/lexer::{token}" in edited and clean,
         "never-compiled buffer, item wrote the import/using pair")

    # 36. the selective `using` grows instead of doubling: the buffer
    #     already selects {token}; completing glyph extends that line.
    broken2 = edited.replace("\nputs go\n", "\nputs go\nputs gly\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": scratch_uri, "version": 3},
            "contentChanges": [{"text": broken2}]}, wait=False)
    c.diagnostics(scratch_uri)
    last_line = broken2.count("\n") - 1
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": scratch_uri},
                    "position": {"line": last_line, "character": 8}})
    items = reply["result"]["items"]
    glyph_item = next((i for i in items if i["label"] == "glyph"), None)
    extends = (glyph_item or {}).get("additionalTextEdits", [])
    new_using = extends[0]["newText"] if extends else ""
    step(36, "completion extends the selective using line",
         glyph_item is not None and len(extends) == 1 and
         new_using == "using calc/lexer::{token, glyph}",
         f"edit: {new_using!r}")

    # 37. fuzzy ranks below prefix but still answers: `ucs` finds
    #     upcase on the receiver, tiered after any prefix match.
    fuzzy_text = app_text.replace("\n  loud\n", "\n  loud.ucs\n")
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 18},
            "contentChanges": [{"text": fuzzy_text}]}, wait=False)
    c.diagnostics(app_uri)
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": app_uri},
                    "position": {"line": 7, "character": 10}})
    items = reply["result"]["items"]
    upcase = next((i for i in items if i["label"] == "upcase"), None)
    step(37, "fuzzy completion finds upcase from ucs",
         upcase is not None and upcase["sortText"].startswith("4"),
         f"{len(items)} item(s), upcase tier "
         f"{upcase and upcase['sortText'][0]!r}")

    # 38. a queued request cancels before it compiles: the didChange
    #     occupies the server, the request and its cancel queue behind,
    #     and the sweep answers -32800 without doing the work.
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 19},
            "contentChanges": [{"text": app_text}]}, wait=False)
    rid = c.request_nowait("workspace/diagnostic", {})
    c.send("$/cancelRequest", {"id": rid}, wait=False)
    reply = c.wait_for(lambda m: m.get("id") == rid)
    step(38, "a queued request cancels before the work",
         reply.get("error", {}).get("code") == -32800,
         f"answer: {reply.get('error', reply.get('result'))!r}")

    # 39. a typing burst is one verdict: didChanges landing while the
    #     server compiles coalesce, so six changes cost at most two
    #     compiles and the verdict is the final text's.
    c.send("textDocument/didChange",
           {"textDocument": {"uri": app_uri, "version": 20},
            "contentChanges": [{"text": app_text + "# 0\n"}]}, wait=False)
    for n in range(5):
        text_n = app_text + f"# burst {n}\n" if n < 4 else app_text
        c.send("textDocument/didChange",
               {"textDocument": {"uri": app_uri, "version": 21 + n},
                "contentChanges": [{"text": text_n}]}, wait=False)
    probe = c.request_nowait("textDocument/documentSymbol",
                             {"textDocument": {"uri": app_uri}})
    published = 0
    while True:
        m = c.read_message()
        if m.get("method") == "textDocument/publishDiagnostics":
            published += 1
            last = m["params"]["diagnostics"]
        if m.get("id") == probe:
            break
    step(39, "a burst of six changes compiles at most twice",
         1 <= published <= 2 and last == [],
         f"{published} publish(es) for 6 didChanges, final verdict clean")

    # 40. document links: the import block is clickable — `import
    #     calc/lexer` and its `using` line both target lexer.iyi.
    reply = c.send("textDocument/documentLink",
                   {"textDocument": {"uri": parser_uri}})
    links = reply["result"] or []
    targets = {l["target"].rsplit("/", 1)[-1] for l in links}
    link_lines = sorted(l["range"]["start"]["line"] for l in links)
    step(40, "documentLink makes the import block clickable",
         targets == {"lexer.iyi"} and link_lines == [2, 3],
         f"{len(links)} link(s) at lines {link_lines}")

    # 41. type hierarchy, upward: Dot's supertypes include the trait
    #     its impl brought in.
    reply = c.send("textDocument/prepareTypeHierarchy",
                   {"textDocument": {"uri": shapes_uri},
                    "position": {"line": 6, "character": 12}})
    items = reply["result"] or []
    dot = items[0] if items else None
    supers = []
    if dot:
        reply = c.send("typeHierarchy/supertypes", {"item": dot})
        supers = reply["result"] or []
    super_names = sorted(s["name"] for s in supers)
    step(41, "type hierarchy climbs from Dot to Paint",
         dot is not None and dot["name"] == "Dot" and dot["kind"] == 23 and
         "Paint" in super_names,
         f"Dot <: {super_names}")

    # 42. and downward: Paint's subtypes include Dot.
    reply = c.send("textDocument/prepareTypeHierarchy",
                   {"textDocument": {"uri": shapes_uri},
                    "position": {"line": 2, "character": 11}})
    items = reply["result"] or []
    paint = items[0] if items else None
    subs = []
    if paint:
        reply = c.send("typeHierarchy/subtypes", {"item": paint})
        subs = reply["result"] or []
    sub_names = sorted(s["name"] for s in subs)
    step(42, "type hierarchy descends from Paint to Dot",
         paint is not None and paint["kind"] == 11 and "Dot" in sub_names,
         f"Paint :> {sub_names}")

    # 43. code lens and its command: the runnable module carries one
    #     lens, and executing it runs the program and returns what it
    #     printed — the released verb, over the wire.
    reply = c.send("textDocument/codeLens",
                   {"textDocument": {"uri": shapes_uri}})
    lenses = reply["result"] or []
    lens = lenses[0] if lenses else None
    ran = {}
    if lens:
        reply = c.send("workspace/executeCommand",
                       {"command": lens["command"]["command"],
                        "arguments": lens["command"]["arguments"]})
        ran = reply["result"] or {}
    step(43, "code lens runs the module over the wire",
         lens is not None and lens["range"]["start"]["line"] == 19 and
         ran.get("ok") and ran.get("output", "").strip() == ".",
         f"lens at line {lens and lens['range']['start']['line'] + 1}, "
         f"output {ran.get('output', '')!r}")

    # 44. snippet completion: a callable with parameters lands with the
    #     cursor inside its parentheses, because initialize said the
    #     client renders snippets.
    snippet_text = edited + "puts yel\n"
    c.send("textDocument/didChange",
           {"textDocument": {"uri": scratch_uri, "version": 5},
            "contentChanges": [{"text": snippet_text}]}, wait=False)
    c.diagnostics(scratch_uri)
    reply = c.send("textDocument/completion",
                   {"textDocument": {"uri": scratch_uri},
                    "position": {"line": snippet_text.count("\n") - 1,
                                 "character": 8}})
    items = reply["result"]["items"]
    yell_item = next((i for i in items if i["label"] == "yell"), None)
    step(44, "completion snippets stop inside the parentheses",
         yell_item is not None and
         yell_item.get("insertText") == "yell($1)" and
         yell_item.get("insertTextFormat") == 2,
         f"insertText {yell_item and yell_item.get('insertText')!r}")

    # 45. semantic tokens delta: one appended line moves a few
    #     integers, not the file's whole stream, and the splice
    #     reconstructs exactly what a full answer says.
    reply = c.send("textDocument/semanticTokens/full",
                   {"textDocument": {"uri": shapes_uri}})
    first = reply["result"]
    c.send("textDocument/didChange",
           {"textDocument": {"uri": shapes_uri, "version": 2},
            "contentChanges": [{"text": shapes_text + "# renk\n"}]},
           wait=False)
    c.diagnostics(shapes_uri)
    reply = c.send("textDocument/semanticTokens/full/delta",
                   {"textDocument": {"uri": shapes_uri},
                    "previousResultId": first["resultId"]})
    delta = reply["result"]
    rebuilt = list(first["data"])
    for e in delta.get("edits", []):
        rebuilt[e["start"]:e["start"] + e["deleteCount"]] = e["data"]
    reply = c.send("textDocument/semanticTokens/full",
                   {"textDocument": {"uri": shapes_uri}})
    fresh = reply["result"]["data"]
    step(45, "semantic token deltas splice to the full answer",
         "edits" in delta and "data" not in delta and rebuilt == fresh,
         f"{len(delta.get('edits', []))} edit(s) over "
         f"{len(first['data'])} ints")

    # 46. shutdown/exit: the server leaves when told, not before.
    c.send("shutdown", {})
    c.send("exit", {}, wait=False)
    step(46, "shutdown then exit", c.proc.wait(timeout=10) == 0)

    print("lsp gate: every step held")


if __name__ == "__main__":
    main()
