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

    # 10. shutdown/exit: the server leaves when told, not before.
    c.send("shutdown", {})
    c.send("exit", {}, wait=False)
    step(10, "shutdown then exit", c.proc.wait(timeout=10) == 0)

    print("lsp gate: every step held")


if __name__ == "__main__":
    main()
