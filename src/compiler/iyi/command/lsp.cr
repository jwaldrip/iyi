# iyi: `iyi lsp` — serve the language over stdio (SPEC.md III.8 #2).
#
# No flags: the protocol negotiates everything a flag would say, and a
# server that is configured outside the protocol is a server that lies to
# its client. The process speaks JSON-RPC on stdin/stdout until the
# client says `exit`; anything a person would want printed goes to the
# client as a response, never to the transport.
require "../lsp/server"

class Iyi::Command
  private def lsp
    if options.first?.in?("--help", "-h")
      puts <<-USAGE
        Usage: #{Command.program_name} lsp

        Speak the Language Server Protocol over stdin/stdout. Point an editor
        at it; there is nothing to configure.

        Beyond LSP 3.17 (hover, definition, document symbols, diagnostics),
        two methods serve agents: `iyi/contextPack` returns the grounding
        pack for a file (`mod context --json` over the wire), and
        `iyi/surface` returns a module's rendered surface (`doc`), unsaved
        buffer included.
        USAGE
      exit
    end
    Lsp::Server.new.run
  end
end
