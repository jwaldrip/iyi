# Editors

`iyi lsp` speaks the Language Server Protocol over stdio and there is
nothing to configure: point a client at the command and every capability
arrives through the protocol — diagnostics on each keystroke from a real
compile, completion that writes the `import`/`using` pair for you,
hover with docs, rename that follows `using` lines, and highlighting as
semantic tokens, so no editor needs a grammar file for `.iyi`.

The one prerequisite everywhere: `iyi` on your `PATH` (or spell the
absolute path where the config names the command).

## VS Code

The extension in [`vscode/`](vscode/) is the whole client — a manifest
and thirty lines that spawn `iyi lsp`:

```console
$ cd editors/vscode
$ npm install
$ npx @vscode/vsce package        # produces iyi-0.1.0.vsix
$ code --install-extension iyi-0.1.0.vsix
```

For hacking on it, open `editors/vscode` in VS Code and press F5.

## Neovim (0.11+)

```lua
vim.filetype.add { extension = { iyi = "iyi" } }
vim.lsp.config("iyi", { cmd = { "iyi", "lsp" }, filetypes = { "iyi" } })
vim.lsp.enable("iyi")
```

## Helix

`~/.config/helix/languages.toml`:

```toml
[language-server.iyi]
command = "iyi"
args = ["lsp"]

[[language]]
name = "iyi"
scope = "source.iyi"
file-types = ["iyi"]
comment-token = "#"
indent = { tab-width = 2, unit = "  " }
language-servers = ["iyi"]
```

## Sublime Text

With the [LSP](https://packagecontrol.io/packages/LSP) package,
`LSP.sublime-settings`:

```json
{
  "clients": {
    "iyi": {
      "enabled": true,
      "command": ["iyi", "lsp"],
      "selector": "source.iyi | text.plain",
      "auto_complete_selector": "source.iyi"
    }
  }
}
```

## Zed, and everything else

Zed registers new languages through its own extension system; the
server side is ready whenever someone writes that shim — command
`iyi lsp`, stdio. The same sentence is the whole integration guide for
any other client: Emacs (eglot), Kate, Acme bridges, and the agent
harnesses that speak LSP directly all need only the command and the
`.iyi` file association.
