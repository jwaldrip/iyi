// The whole client: spawn `iyi lsp`, hand it `.iyi` documents. The
// protocol negotiates everything else — highlighting arrives as
// semantic tokens, quickfixes as code actions, the import pair as
// completion edits — which is why this file has nothing to say.
const { workspace } = require("vscode");
const { LanguageClient } = require("vscode-languageclient/node");

let client;

function activate() {
  const command =
    workspace.getConfiguration("iyi").get("serverPath") || "iyi";
  client = new LanguageClient(
    "iyi",
    "iyi language server",
    { command, args: ["lsp"] },
    { documentSelector: [{ scheme: "file", language: "iyi" }] }
  );
  client.start();
}

function deactivate() {
  return client ? client.stop() : undefined;
}

module.exports = { activate, deactivate };
