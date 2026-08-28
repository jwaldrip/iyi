# iyi: `iyi lsp` — the language server SPEC.md III.8 #2 said R-1 makes
# nearly free, built as exactly that.
#
# A language server for an open-class language keeps an incremental model
# of the whole program and prays its invalidation story is right. iyi's
# unit is the module, compiled alone against its imports' *declarations*,
# so this server keeps **no semantic state at all**: every request runs
# the real front end on the module under the cursor — the same code, the
# same errors, the same answers a build would give — and is fast because
# the language made the unit small, not because a cache is guessing.
#
# What it speaks (LSP 3.17, the subset that earns its keep):
#
#   textDocument/didOpen · didChange · didSave · didClose — full-text
#     sync; every change publishes diagnostics from a real compile of the
#     buffer, unsaved and half-broken included
#   textDocument/hover          — the name's type, from the typed AST
#   textDocument/definition     — where the call or type is defined
#   textDocument/documentSymbol — the file's outline, from the parser
#
# And two methods no other server has, because no other language wrote
# its interfaces down (AI_FIRST.md §2):
#
#   iyi/contextPack — the grounding pack for a file: every import's exact
#     exported surface, no bodies; what a model reads before editing
#   iyi/surface     — one module's rendered surface, doc comments included
#
# Diagnostics carry the house style as data: when the message cites a
# SPEC section, the section rides in `code` and `codeDescription` links
# to the spec itself. An error that names its rule is an error an editor
# can teach with.
#
# Unsaved sibling buffers reach the compiler as `iyi_file_overrides`:
# one hash of path → buffer the resolver and `import_file` consult
# before the disk, so an import finds what the person sees, saved or
# not. No shadow tree, no virtual file system — the same resolution a
# build does, reading a buffer where it would have read the file.
require "json"
require "uri"
require "./analysis"
require "./outline"

module Iyi::Lsp
  class Server
    @documents = {} of String => String # uri => current text
    @running = true
    @analysis = Analysis.new

    def initialize(@input : IO = STDIN, @output : IO = STDOUT)
    end

    def run : Nil
      while @running
        message = read_message
        break unless message
        handle(message)
      end
    end

    # ── Transport: Content-Length framed JSON-RPC over stdio ────────────

    private def read_message : JSON::Any?
      length = nil
      while line = @input.gets(chomp: false)
        line = line.chomp
        break if line.empty?
        if line.starts_with?("Content-Length:")
          length = line.split(':')[1].strip.to_i
        end
      end
      return nil unless length
      body = Bytes.new(length)
      @input.read_fully(body)
      JSON.parse(String.new(body))
    rescue IO::EOFError
      nil
    end

    private def send(payload : String) : Nil
      @output << "Content-Length: " << payload.bytesize << "\r\n\r\n" << payload
      @output.flush
    end

    private def respond(id : JSON::Any, & : JSON::Builder -> _) : Nil
      send(JSON.build do |json|
        json.object do
          json.field "jsonrpc", "2.0"
          json.field "id" { id.to_json(json) }
          json.field "result" { yield json }
        end
      end)
    end

    private def respond_null(id : JSON::Any) : Nil
      respond(id, &.null)
    end

    private def notify(method : String, & : JSON::Builder -> _) : Nil
      send(JSON.build do |json|
        json.object do
          json.field "jsonrpc", "2.0"
          json.field "method", method
          json.field "params" { yield json }
        end
      end)
    end

    # ── Dispatch ─────────────────────────────────────────────────────────

    private def handle(message : JSON::Any) : Nil
      method = message["method"]?.try(&.as_s?)
      id = message["id"]?
      params = message["params"]?

      case method
      when "initialize"
        respond(id.not_nil!) { |json| capabilities(json) }
      when "initialized"
        # A notification; nothing to say back.
      when "shutdown"
        respond_null(id.not_nil!)
      when "exit"
        @running = false
      when "textDocument/didOpen"
        uri = params.not_nil!["textDocument"]["uri"].as_s
        @documents[uri] = params.not_nil!["textDocument"]["text"].as_s
        publish_diagnostics(uri)
      when "textDocument/didChange"
        uri = params.not_nil!["textDocument"]["uri"].as_s
        # Full sync: the last change carries the whole text.
        @documents[uri] = params.not_nil!["contentChanges"].as_a.last["text"].as_s
        publish_diagnostics(uri)
      when "textDocument/didSave"
        publish_diagnostics(params.not_nil!["textDocument"]["uri"].as_s)
      when "textDocument/didClose"
        uri = params.not_nil!["textDocument"]["uri"].as_s
        @documents.delete(uri)
      when "textDocument/hover"
        on_hover(id.not_nil!, params.not_nil!)
      when "textDocument/definition"
        on_definition(id.not_nil!, params.not_nil!)
      when "textDocument/documentSymbol"
        on_document_symbol(id.not_nil!, params.not_nil!)
      when "iyi/contextPack"
        on_delegated(id.not_nil!, params.not_nil!, "mod", "context", "--json")
      when "iyi/surface"
        on_delegated(id.not_nil!, params.not_nil!, "doc")
      else
        # A request we do not speak gets an empty answer rather than an
        # error, so a chatty client keeps working; a notification is
        # silence either way.
        respond_null(id) if id
      end
    rescue ex
      # A single bad request must not take the session down: the server's
      # whole value is being there on the next keystroke.
      if id
        send(JSON.build do |json|
          json.object do
            json.field "jsonrpc", "2.0"
            json.field "id" { id.to_json(json) }
            json.field "error" do
              json.object do
                json.field "code", -32603
                json.field "message", ex.message.to_s
              end
            end
          end
        end)
      end
    end

    private def capabilities(json : JSON::Builder) : Nil
      json.object do
        json.field "capabilities" do
          json.object do
            json.field "textDocumentSync" do
              json.object do
                json.field "openClose", true
                json.field "change", 1 # full
                json.field "save", true
              end
            end
            json.field "hoverProvider", true
            json.field "definitionProvider", true
            json.field "documentSymbolProvider", true
          end
        end
        json.field "serverInfo" do
          json.object do
            json.field "name", "iyi"
            json.field "version", Iyi::Config.iyi_version
          end
        end
      end
    end

    # ── Diagnostics ──────────────────────────────────────────────────────

    private def publish_diagnostics(uri : String) : Nil
      path = path_of(uri)
      text = text_of(uri)
      lines = text.lines
      _, diags = @analysis.check(path, text, overrides_for(path))

      notify("textDocument/publishDiagnostics") do |json|
        json.object do
          json.field "uri", uri
          json.field "diagnostics" do
            json.array do
              diags.each do |diag|
                line_text = lines[diag.line - 1]? || ""
                start_ch = Lsp.character_of(line_text, diag.column)
                end_ch = diag.size > 0 ? Lsp.character_of(line_text, diag.column + diag.size) : start_ch
                json.object do
                  json.field "range" { range(json, diag.line - 1, start_ch, diag.line - 1, end_ch) }
                  json.field "severity", 1
                  json.field "source", "iyi"
                  json.field "message", diag.message
                  if refs = diag.spec
                    json.field "code", "SPEC #{refs.first}"
                    json.field "codeDescription" do
                      json.object do
                        json.field "href", "https://github.com/sdogruyol/iyi/blob/master/SPEC.md"
                      end
                    end
                  end
                  unless diag.related.empty?
                    json.field "relatedInformation" do
                      json.array do
                        diag.related.each do |(file, line, col, msg)|
                          json.object do
                            json.field "location" do
                              json.object do
                                json.field "uri", uri_of(file)
                                json.field "range" { range(json, line - 1, col > 0 ? col - 1 : 0, line - 1, col > 0 ? col - 1 : 0) }
                              end
                            end
                            json.field "message", msg
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    # ── Hover ────────────────────────────────────────────────────────────

    private def on_hover(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      column = Lsp.column_of(line_text, char)

      word = word_at(line_text, column)
      result = @analysis.context_at(path, text, overrides_for(path), line0 + 1, column)
      contexts = result.try(&.contexts)
      unless contexts && !contexts.empty?
        return respond_null(id)
      end

      # The name under the cursor first; a call expression the visitor
      # keyed by its own text second. Never the whole scope: hover is a
      # question about one thing.
      entry = nil
      contexts.each do |ctx|
        if word && (type = ctx[word]?)
          entry = {word, type}
          break
        end
      end
      unless entry
        contexts.each do |ctx|
          ctx.each do |key, type|
            if word && (key == word || key.ends_with?(".#{word}") || key.starts_with?("#{word}("))
              entry = {key, type}
              break
            end
          end
          break if entry
        end
      end
      return respond_null(id) unless entry

      name, type = entry
      typename = PrettyTypeNameJsonConverter.pretty_type_name(type)
      respond(id) do |json|
        json.object do
          json.field "contents" do
            json.object do
              json.field "kind", "markdown"
              json.field "value", "```iyi\n#{name} : #{typename}\n```"
            end
          end
        end
      end
    end

    # The identifier under the cursor: iyi's name characters, plus the
    # `@`/`@@` sigils and the `?`/`!` suffixes.
    private def word_at(line_text : String, column : Int32) : String?
      chars = line_text.chars
      index = column - 1
      index = chars.size - 1 if index >= chars.size
      return nil if index < 0

      name_char = ->(ch : Char) { ch.alphanumeric? || ch == '_' }
      return nil unless name_char.call(chars[index]) || chars[index].in?('?', '!', '@')

      from = index
      while from > 0 && name_char.call(chars[from - 1])
        from -= 1
      end
      while from > 0 && chars[from - 1] == '@'
        from -= 1
      end
      to = index
      while to < chars.size - 1 && name_char.call(chars[to + 1])
        to += 1
      end
      to += 1 if to < chars.size - 1 && chars[to + 1].in?('?', '!')
      line_text[from..to]
    end

    # ── Definition ───────────────────────────────────────────────────────

    private def on_definition(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      column = Lsp.column_of(line_text, char)

      result = @analysis.implementations_at(path, text, overrides_for(path), line0 + 1, column)
      traces = result.try(&.implementations)
      unless traces && !traces.empty?
        return respond_null(id)
      end

      respond(id) do |json|
        json.array do
          traces.each do |trace|
            next if trace.filename == "<unknown>" || trace.line <= 0
            target_line = read_line(trace.filename, trace.line)
            ch = Lsp.character_of(target_line, trace.column)
            json.object do
              json.field "uri", uri_of(trace.filename)
              json.field "range" { range(json, trace.line - 1, ch, trace.line - 1, ch) }
            end
          end
        end
      end
    end

    private def read_line(filename : String, line : Int32) : String
      text = @documents[uri_of(filename)]? || (File.file?(filename) ? File.read(filename) : "")
      text.lines[line - 1]? || ""
    end

    # ── Document symbols ─────────────────────────────────────────────────

    private def on_document_symbol(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      text = text_of(uri)
      symbols = Outline.build(text, path_of(uri))
      lines = text.lines
      respond(id) do |json|
        json.array do
          symbols.each { |sym| document_symbol(json, sym, lines) }
        end
      end
    end

    private def document_symbol(json : JSON::Builder, sym : Outline::Sym, lines : Array(String)) : Nil
      name_line = lines[sym.name_line - 1]? || ""
      sel_start = Lsp.character_of(name_line, sym.name_column)
      sel_end = Lsp.character_of(name_line, sym.name_column + sym.name.size)
      json.object do
        json.field "name", sym.name
        json.field "kind", sym.kind
        json.field "range" { range(json, sym.line - 1, 0, sym.end_line - 1, (lines[sym.end_line - 1]? || "").size) }
        json.field "selectionRange" { range(json, sym.name_line - 1, sel_start, sym.name_line - 1, sel_end) }
        unless sym.children.empty?
          json.field "children" do
            json.array do
              sym.children.each { |child| document_symbol(json, child, lines) }
            end
          end
        end
      end
    end

    # ── The agent endpoints: the CLI's own verbs over the wire ───────────

    # `iyi/contextPack` and `iyi/surface` run the released verbs against
    # the document — the same output `iyi mod context --json` and
    # `iyi doc` print, framed as a response. A dirty buffer is
    # materialised beside the file first, so the pack grounds what the
    # editor sees, not what the disk last saw.
    private def on_delegated(id : JSON::Any, params : JSON::Any, *verb : String) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)

      scratch = nil
      if (text = @documents[uri]?) && (!File.file?(path) || File.read(path) != text)
        scratch = File.join(File.dirname(path), ".#{File.basename(path, ".iyi")}.iyi-lsp.iyi")
        File.write(scratch, text)
        path = scratch
      end

      output = IO::Memory.new
      error = IO::Memory.new
      status = Process.run(
        Process.executable_path.not_nil!,
        verb.to_a + [path],
        output: output, error: error)

      respond(id) do |json|
        json.object do
          json.field "ok", status.success?
          json.field "output", output.to_s
          json.field "error", error.to_s unless status.success?
        end
      end
    ensure
      File.delete(scratch) if scratch && File.file?(scratch)
    end

    # ── Paths and the shadow root ────────────────────────────────────────

    private def path_of(uri : String) : String
      URI.decode(uri.lchop("file://"))
    end

    private def uri_of(path : String) : String
      "file://" + path
    end

    private def text_of(uri : String) : String
      @documents[uri]? || File.read(path_of(uri))
    end

    private def range(json : JSON::Builder, l0 : Int32, c0 : Int32, l1 : Int32, c1 : Int32) : Nil
      json.object do
        json.field "start" do
          json.object do
            json.field "line", l0
            json.field "character", c0
          end
        end
        json.field "end" do
          json.object do
            json.field "line", l1
            json.field "character", c1
          end
        end
      end
    end

    # Every open buffer except the one being compiled, keyed by the path
    # its file would have — the compiler reads these before the disk, so
    # cross-module answers see unsaved edits.
    private def overrides_for(path : String) : Hash(String, String)
      overrides = {} of String => String
      @documents.each do |uri, text|
        doc_path = path_of(uri)
        overrides[doc_path] = text unless doc_path == path
      end
      overrides
    end
  end
end
