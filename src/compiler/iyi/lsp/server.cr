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
#   textDocument/didOpen · didChange · didSave · didClose — incremental
#     sync; every change publishes diagnostics from a real compile of the
#     buffer, unsaved and half-broken included
#   textDocument/hover          — the name's type, the def's signature
#     and doc comment
#   textDocument/definition     — where the call or type is defined
#   textDocument/typeDefinition — where the name's *type* is declared
#   textDocument/documentSymbol — the file's outline, from the parser
#   textDocument/documentHighlight · foldingRange · workspace/symbol
#   textDocument/completion · references · rename (with prepare)
#   textDocument/signatureHelp  — overloads while the call is half-typed
#   textDocument/formatting     — the formatter, in process
#   textDocument/inlayHint      — inferred types and parameter names
#   textDocument/codeAction     — the compiler's own "did you mean",
#     made clickable
#   textDocument/semanticTokens — highlighting from the lexer, so any
#     client colors iyi with no grammar installed
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
require "./tokens"
require "../tools/formatter"

module Iyi::Lsp
  class Server
    @documents = {} of String => String # uri => current text
    # The last published diagnostics, kept for codeAction to read back:
    # {line0, start_ch, end_ch, message} per document.
    @published = {} of String => Array({Int32, Int32, Int32, String})
    @root : String?
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
        @root = root_of(params)
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
        # Incremental sync: each change names a range in wire units, or
        # carries the whole text; both apply in order.
        text = @documents[uri]? || ""
        params.not_nil!["contentChanges"].as_a.each do |change|
          text = apply_change(text, change)
        end
        @documents[uri] = text
        publish_diagnostics(uri)
      when "textDocument/didSave"
        publish_diagnostics(params.not_nil!["textDocument"]["uri"].as_s)
      when "textDocument/didClose"
        uri = params.not_nil!["textDocument"]["uri"].as_s
        @documents.delete(uri)
        @published.delete(uri)
      when "textDocument/hover"
        on_hover(id.not_nil!, params.not_nil!)
      when "textDocument/definition"
        on_definition(id.not_nil!, params.not_nil!)
      when "textDocument/documentSymbol"
        on_document_symbol(id.not_nil!, params.not_nil!)
      when "textDocument/completion"
        on_completion(id.not_nil!, params.not_nil!)
      when "textDocument/references"
        on_references(id.not_nil!, params.not_nil!)
      when "textDocument/rename"
        on_rename(id.not_nil!, params.not_nil!)
      when "textDocument/prepareRename"
        on_prepare_rename(id.not_nil!, params.not_nil!)
      when "textDocument/typeDefinition"
        on_type_definition(id.not_nil!, params.not_nil!)
      when "textDocument/documentHighlight"
        on_document_highlight(id.not_nil!, params.not_nil!)
      when "textDocument/signatureHelp"
        on_signature_help(id.not_nil!, params.not_nil!)
      when "textDocument/formatting"
        on_formatting(id.not_nil!, params.not_nil!)
      when "textDocument/foldingRange"
        on_folding_range(id.not_nil!, params.not_nil!)
      when "workspace/symbol"
        on_workspace_symbol(id.not_nil!, params.not_nil!)
      when "textDocument/semanticTokens/full"
        on_semantic_tokens(id.not_nil!, params.not_nil!)
      when "textDocument/inlayHint"
        on_inlay_hint(id.not_nil!, params.not_nil!)
      when "textDocument/codeAction"
        on_code_action(id.not_nil!, params.not_nil!)
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
                json.field "change", 2 # incremental
                json.field "save", true
              end
            end
            json.field "hoverProvider", true
            json.field "definitionProvider", true
            json.field "typeDefinitionProvider", true
            json.field "documentSymbolProvider", true
            json.field "documentHighlightProvider", true
            json.field "referencesProvider", true
            json.field "documentFormattingProvider", true
            json.field "foldingRangeProvider", true
            json.field "workspaceSymbolProvider", true
            json.field "inlayHintProvider", true
            json.field "renameProvider" do
              json.object { json.field "prepareProvider", true }
            end
            json.field "codeActionProvider" do
              json.object do
                json.field "codeActionKinds" { json.array { json.string "quickfix" } }
              end
            end
            json.field "completionProvider" do
              json.object do
                json.field "triggerCharacters" { json.array { json.string "." } }
              end
            end
            json.field "signatureHelpProvider" do
              json.object do
                json.field "triggerCharacters" do
                  json.array do
                    json.string "("
                    json.string ","
                  end
                end
              end
            end
            json.field "semanticTokensProvider" do
              json.object do
                json.field "legend" do
                  json.object do
                    json.field "tokenTypes" do
                      json.array { Tokens::TYPES.each { |name| json.string name } }
                    end
                    json.field "tokenModifiers" { json.array { } }
                  end
                end
                json.field "full", true
              end
            end
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

      rows = diags.map do |diag|
        line_text = lines[diag.line - 1]? || ""
        start_ch = Lsp.character_of(line_text, diag.column)
        end_ch = diag.size > 0 ? Lsp.character_of(line_text, diag.column + diag.size) : start_ch
        {diag.line - 1, start_ch, end_ch, diag}
      end

      # codeAction reads these back: a quickfix is a diagnostic whose
      # message already names the fix.
      @published[uri] = rows.map { |(line0, start_ch, end_ch, diag)| {line0, start_ch, end_ch, diag.message} }

      notify("textDocument/publishDiagnostics") do |json|
        json.object do
          json.field "uri", uri
          json.field "diagnostics" do
            json.array do
              rows.each do |(line0, start_ch, end_ch, diag)|
                json.object do
                  json.field "range" { range(json, line0, start_ch, line0, end_ch) }
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
      parts = [] of String

      result = @analysis.context_at(path, text, overrides_for(path), line0 + 1, column)
      if (contexts = result.try(&.contexts)) && !contexts.empty?
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
        if entry
          name, type = entry
          parts << "```iyi\n#{name} : #{PrettyTypeNameJsonConverter.pretty_type_name(type)}\n```"
        end
      end

      # A call's definition rides along: its signature as the author
      # wrote it, the doc comment above it. The compile is the memoised
      # one the type answer already paid for.
      impls = @analysis.implementations_at(path, text, overrides_for(path), line0 + 1, column)
      if trace = impls.try(&.implementations).try(&.find { |t| t.filename != "<unknown>" && t.line > 0 })
        signature = read_line(trace.filename, trace.line).strip
        unless signature.empty?
          parts << "```iyi\n#{signature}\n```"
          doc = doc_above(trace.filename, trace.line)
          parts << doc unless doc.empty?
        end
      end

      return respond_null(id) if parts.empty?

      respond(id) do |json|
        json.object do
          json.field "contents" do
            json.object do
              json.field "kind", "markdown"
              json.field "value", parts.uniq.join("\n\n---\n\n")
            end
          end
        end
      end
    end

    # The `#` lines immediately above a definition — the doc comment,
    # rendered as the markdown it already is.
    private def doc_above(filename : String, line : Int32) : String
      text = @documents[uri_of(filename)]? || (File.file?(filename) ? File.read(filename) : "")
      lines = text.lines
      docs = [] of String
      index = line - 2
      while index >= 0
        stripped = lines[index]?.try(&.strip)
        break unless stripped && stripped.starts_with?('#')
        docs << stripped.lchop('#').lchop(' ')
        index -= 1
      end
      docs.reverse!.join('\n')
    end

    # The identifier under the cursor: iyi's name characters, plus the
    # `@`/`@@` sigils and the `?`/`!` suffixes. The range is inclusive
    # codepoint indexes into the line, 0-based.
    private def word_range(line_text : String, column : Int32) : {Int32, Int32}?
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
      {from, to}
    end

    private def word_at(line_text : String, column : Int32) : String?
      word_range(line_text, column).try { |(from, to)| line_text[from..to] }
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

    # ── Completion ───────────────────────────────────────────────────────

    KEYWORDS = %w(def end if elsif else unless while case when import using
      pub module trait impl struct class enum return begin rescue ensure
      true false nil self group spawn defer select)

    private def on_completion(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""

      # Everything below is in codepoints; the wire's UTF-16 enters and
      # leaves through the two converters only.
      cursor = Lsp.column_of(line_text, char) - 1
      chars = line_text.chars

      prefix_start = cursor
      while prefix_start > 0 && name_char?(chars[prefix_start - 1]?)
        prefix_start -= 1
      end
      prefix = chars[prefix_start...cursor].join

      receiver = nil
      anchor = prefix_start
      if prefix_start > 0 && chars[prefix_start - 1]? == '.'
        receiver_start = prefix_start - 1
        while receiver_start > 0 && (name_char?(chars[receiver_start - 1]?) || chars[receiver_start - 1]? == '@')
          receiver_start -= 1
        end
        receiver = chars[receiver_start...(prefix_start - 1)].join
        anchor = receiver_start
        return respond_null(id) if receiver.empty?
      end

      items = @analysis.completion_at(
        path, text, overrides_for(path), line0 + 1, anchor + 1, receiver)
      items.select! { |(label, _, _)| label.starts_with?(prefix) } unless prefix.empty?
      if receiver.nil?
        KEYWORDS.each do |keyword|
          items << {keyword, "keyword", 14} if prefix.empty? || keyword.starts_with?(prefix)
        end
      end

      respond(id) do |json|
        json.object do
          json.field "isIncomplete", false
          json.field "items" do
            json.array do
              items.each do |(label, detail, kind)|
                json.object do
                  json.field "label", label
                  json.field "kind", kind
                  json.field "detail", detail
                  # Scope first, methods next, keywords last.
                  json.field "sortText", "#{kind == 6 ? '0' : kind == 14 ? '2' : '1'}#{label}"
                end
              end
            end
          end
        end
      end
    end

    private def name_char?(ch : Char?) : Bool
      return false unless ch
      ch.alphanumeric? || ch == '_'
    end

    # ── References and rename ────────────────────────────────────────────

    private def on_references(id : JSON::Any, params : JSON::Any) : Nil
      references, declarations = reference_sites(params)
      if references.empty? && declarations.empty?
        return respond_null(id)
      end

      include_declaration = params["context"]?.try(&.["includeDeclaration"]?).try(&.as_bool?) || false
      sites = references.dup
      sites.concat declarations if include_declaration

      respond(id) do |json|
        json.array do
          sites.each do |(location, size)|
            filename = location.filename
            next unless filename.is_a?(String)
            target_line = read_line(filename, location.line_number)
            start_ch = Lsp.character_of(target_line, location.column_number)
            end_ch = Lsp.character_of(target_line, location.column_number + size)
            json.object do
              json.field "uri", uri_of(filename)
              json.field "range" { range(json, location.line_number - 1, start_ch, location.line_number - 1, end_ch) }
            end
          end
        end
      end
    end

    # Rename rides the same typed graph as references: only the edges the
    # front end bound move, so an overload that shares the name but not
    # the resolution keeps it. What the graph does not know it refuses to
    # touch — by name, not silently.
    private def on_rename(id : JSON::Any, params : JSON::Any) : Nil
      new_name = params["newName"].as_s
      unless valid_name?(new_name)
        raise "'#{new_name}' is not an iyi method name"
      end

      references, declarations = reference_sites(params)
      if references.empty? && declarations.empty?
        raise "nothing renameable under the cursor: rename serves defs and their calls, off the typed graph"
      end

      by_file = {} of String => Array({Int32, Int32, Int32})
      (declarations + references).each do |(location, size)|
        filename = location.filename
        next unless filename.is_a?(String)
        target_line = read_line(filename, location.line_number)
        start_ch = Lsp.character_of(target_line, location.column_number)
        end_ch = Lsp.character_of(target_line, location.column_number + size)
        (by_file[filename] ||= [] of {Int32, Int32, Int32}) << {location.line_number - 1, start_ch, end_ch}
      end
      by_file.each_value(&.uniq!)

      respond(id) do |json|
        json.object do
          json.field "changes" do
            json.object do
              by_file.each do |filename, edits|
                json.field uri_of(filename) do
                  json.array do
                    edits.each do |(line0, start_ch, end_ch)|
                      json.object do
                        json.field "range" { range(json, line0, start_ch, line0, end_ch) }
                        json.field "newText", new_name
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

    # Under R-1 a def's callers live in its *consumers'* compiles, so one
    # program cannot answer "who calls this" — the session can: every open
    # document is compiled as its own entry and the answers merge. The
    # per-entry cost is the same 30–80 ms a keystroke already pays.
    private def reference_sites(params : JSON::Any) : {Array({Location, Int32}), Array({Location, Int32})}
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      target = Location.new(path, line0 + 1, Lsp.column_of(line_text, char))

      entries = @documents.map { |doc_uri, doc_text| {path_of(doc_uri), doc_text} }
      entries << {path, text} unless @documents.has_key?(uri)

      references = [] of {Location, Int32}
      declarations = [] of {Location, Int32}
      entries.each do |(entry_path, entry_text)|
        visitor = @analysis.references_at(entry_path, entry_text, overrides_for(entry_path), target)
        next unless visitor
        references.concat visitor.references
        declarations.concat visitor.declarations
      end

      {dedupe(references), dedupe(declarations)}
    end

    private def dedupe(sites : Array({Location, Int32})) : Array({Location, Int32})
      seen = Set({String, Int32, Int32}).new
      sites.select do |(location, _)|
        seen.add?({location.filename.to_s, location.line_number, location.column_number})
      end
    end

    private def valid_name?(name : String) : Bool
      return false if name.empty?
      return false unless name[0].ascii_letter? || name[0] == '_'
      body = name.ends_with?('?') || name.ends_with?('!') ? name.rchop : name
      return false if body.empty?
      body.each_char.all? { |ch| ch.alphanumeric? || ch == '_' }
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

    # ── Prepare rename ───────────────────────────────────────────────────

    # Rename begins with the question references answer — is the cursor
    # on the typed graph at all — asked of this buffer alone, so the
    # refusal is instant and named before the client opens an input box.
    private def on_prepare_rename(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      column = Lsp.column_of(line_text, char)

      target = Location.new(path, line0 + 1, column)
      visitor = @analysis.references_at(path, text, overrides_for(path), target)
      span = word_range(line_text, column)
      return respond_null(id) unless visitor && span

      from, to = span
      start_ch = Lsp.character_of(line_text, from + 1)
      end_ch = Lsp.character_of(line_text, to + 2)
      respond(id) do |json|
        json.object do
          json.field "range" { range(json, line0, start_ch, line0, end_ch) }
          json.field "placeholder", line_text[from..to]
        end
      end
    end

    # ── Type definition ──────────────────────────────────────────────────

    private def on_type_definition(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      column = Lsp.column_of(line_text, char)

      locations = @analysis.type_locations_at(
        path, text, overrides_for(path), line0 + 1, column, word_at(line_text, column))
      return respond_null(id) if locations.empty?

      respond(id) do |json|
        json.array do
          locations.each do |location|
            filename = location.filename
            next unless filename.is_a?(String)
            target_line = read_line(filename, location.line_number)
            ch = Lsp.character_of(target_line, location.column_number)
            json.object do
              json.field "uri", uri_of(filename)
              json.field "range" { range(json, location.line_number - 1, ch, location.line_number - 1, ch) }
            end
          end
        end
      end
    end

    # ── Document highlight ───────────────────────────────────────────────

    # References, scoped to the buffer under the cursor: one compile,
    # the sites in this file only, the declaration marked as the write.
    private def on_document_highlight(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      line_text = text.lines[line0]? || ""
      target = Location.new(path, line0 + 1, Lsp.column_of(line_text, char))

      visitor = @analysis.references_at(path, text, overrides_for(path), target)
      return respond_null(id) unless visitor

      respond(id) do |json|
        json.array do
          {visitor.declarations, visitor.references}.each_with_index do |sites, group|
            sites.each do |(location, size)|
              next unless location.filename == path
              target_line = read_line(path, location.line_number)
              start_ch = Lsp.character_of(target_line, location.column_number)
              end_ch = Lsp.character_of(target_line, location.column_number + size)
              json.object do
                json.field "range" { range(json, location.line_number - 1, start_ch, location.line_number - 1, end_ch) }
                json.field "kind", group.zero? ? 3 : 2 # Write the def, Read the calls
              end
            end
          end
        end
      end
    end

    # ── Signature help ───────────────────────────────────────────────────

    # The half-typed call is found by text — the buffer stopped parsing
    # the moment the `(` landed — and its overloads by the typed graph:
    # the callee resolves in the scope the cursor sits in, off the last
    # compile that held together.
    private def on_signature_help(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      line0 = params["position"]["line"].as_i
      char = params["position"]["character"].as_i
      lines = text.lines
      line_text = lines[line0]? || ""
      cursor = Lsp.column_of(line_text, char) - 1

      call = enclosing_call(lines, line0, cursor)
      return respond_null(id) unless call
      receiver, name, commas = call

      signatures = @analysis.signatures_at(
        path, text, overrides_for(path), line0 + 1,
        Lsp.column_of(line_text, char), receiver, name)
      return respond_null(id) if signatures.empty?

      active = signatures.index { |sig| sig.params.size > commas } || 0
      respond(id) do |json|
        json.object do
          json.field "activeSignature", active
          json.field "activeParameter", commas
          json.field "signatures" do
            json.array do
              signatures.each do |sig|
                json.object do
                  json.field "label", sig.label
                  if doc = sig.doc
                    json.field "documentation", doc
                  end
                  json.field "parameters" do
                    json.array do
                      sig.params.each do |param|
                        json.object { json.field "label", param }
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

    # Walk backwards from the cursor to the unclosed `(`, counting the
    # commas at its depth; what precedes it is the callee, maybe with a
    # `receiver.` in front. Text, not syntax — the buffer mid-call has
    # no syntax yet — and bounded, so a pathological file cannot stall
    # a keystroke. Returns {receiver, name, commas-before-cursor}.
    private def enclosing_call(lines : Array(String), line0 : Int32, cursor : Int32) : {String?, String, Int32}?
      chars = [] of Char
      ({line0 - 40, 0}.max...line0).each do |index|
        chars.concat (lines[index]? || "").chars
        chars << '\n'
      end
      line_chars = (lines[line0]? || "").chars
      chars.concat line_chars[0, {cursor, line_chars.size}.min]

      depth = 0
      commas = 0
      found = -1
      index = chars.size - 1
      while index >= 0
        case chars[index]
        when ')', ']', '}'
          depth += 1
        when '[', '{'
          depth -= 1 if depth > 0
        when '('
          if depth.zero?
            found = index
            break
          end
          depth -= 1
        when ','
          commas += 1 if depth.zero?
        end
        index -= 1
      end
      return nil if found <= 0

      name_end = found - 1
      from = chars[name_end].in?('?', '!') ? name_end - 1 : name_end
      while from >= 0 && name_char?(chars[from])
        from -= 1
      end
      name = chars[(from + 1)..name_end].join
      return nil if name.empty?
      return nil unless name[0].ascii_letter? || name[0] == '_'
      return nil if name[0].ascii_uppercase? # `Foo(` instantiates a generic

      receiver = nil
      if from >= 0 && chars[from] == '.'
        rec_end = from - 1
        rec_from = rec_end
        while rec_from >= 0 && (name_char?(chars[rec_from]) || chars[rec_from] == '@')
          rec_from -= 1
        end
        if rec_end >= 0 && rec_end > rec_from
          receiver = chars[(rec_from + 1)..rec_end].join
        end
      end

      {receiver, name, commas}
    end

    # ── Formatting ───────────────────────────────────────────────────────

    # The formatter, in process: the same `Iyi.format` the CLI verb
    # runs, answered as one whole-document edit. A buffer that does not
    # parse keeps its bytes — the diagnostics channel already says why.
    private def on_formatting(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      text = text_of(uri)
      formatted =
        begin
          Iyi.format(text, filename: path_of(uri))
        rescue CodeError
          return respond_null(id)
        end
      return respond(id) { |json| json.array { } } if formatted == text

      lines = text.split('\n')
      end_line0 = lines.size - 1
      end_ch = Lsp.character_of(lines[end_line0], lines[end_line0].size + 1)
      respond(id) do |json|
        json.array do
          json.object do
            json.field "range" { range(json, 0, 0, end_line0, end_ch) }
            json.field "newText", formatted
          end
        end
      end
    end

    # ── Folding ranges ───────────────────────────────────────────────────

    # Declarations fold off the outline; comment blocks and the import
    # header fold off the text — all of it survives a buffer that does
    # not compile.
    private def on_folding_range(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      text = text_of(uri)
      folds = [] of {Int32, Int32, String?}
      collect_symbol_folds(Outline.build(text, path_of(uri)), folds)

      lines = text.lines
      run_start = nil
      run_kind = nil
      lines.each_with_index do |line, index|
        stripped = line.strip
        kind =
          if stripped.starts_with?('#')
            "comment"
          elsif stripped.starts_with?("import ") || stripped.starts_with?("using ")
            "imports"
          end
        next if kind == run_kind
        if (start = run_start) && (ended = run_kind) && index - 1 > start
          folds << {start, index - 1, ended}
        end
        run_start = kind ? index : nil
        run_kind = kind
      end
      if (start = run_start) && (ended = run_kind) && lines.size - 1 > start
        folds << {start, lines.size - 1, ended}
      end

      respond(id) do |json|
        json.array do
          folds.each do |(start_line, end_line, kind)|
            json.object do
              json.field "startLine", start_line
              json.field "endLine", end_line
              json.field "kind", kind if kind
            end
          end
        end
      end
    end

    private def collect_symbol_folds(symbols : Array(Outline::Sym), into : Array({Int32, Int32, String?})) : Nil
      symbols.each do |sym|
        into << {sym.line - 1, sym.end_line - 1, nil} if sym.end_line > sym.line
        collect_symbol_folds(sym.children, into)
      end
    end

    # ── Workspace symbols ────────────────────────────────────────────────

    # Every `.iyi` file the workspace holds, open buffers winning over
    # the disk, outlined by the parser and filtered by subsequence — the
    # match every editor's muscle memory expects. No index: parsing a
    # module costs microseconds, and an index is a cache with an
    # invalidation story.
    private def on_workspace_symbol(id : JSON::Any, params : JSON::Any) : Nil
      query = params["query"]?.try(&.as_s?) || ""

      paths = @documents.keys.map { |doc_uri| path_of(doc_uri) }
      if root = @root
        Dir.glob(File.join(root, "**", "*.iyi")) do |file|
          next if file.includes?("/.") || file.includes?("/lib/")
          paths << file unless paths.includes?(file)
          break if paths.size >= 2000
        end
      end

      results = [] of {String, Int32, String, Int32, Int32, Int32, String?}
      paths.each do |file|
        text = @documents[uri_of(file)]? || (File.file?(file) ? File.read(file) : nil)
        next unless text
        collect_workspace_symbols(Outline.build(text, file), file, text.lines, query, nil, results)
        break if results.size >= 400
      end

      respond(id) do |json|
        json.array do
          results.each do |(name, kind, file, line0, start_ch, end_ch, container)|
            json.object do
              json.field "name", name
              json.field "kind", kind
              json.field "location" do
                json.object do
                  json.field "uri", uri_of(file)
                  json.field "range" { range(json, line0, start_ch, line0, end_ch) }
                end
              end
              json.field "containerName", container if container
            end
          end
        end
      end
    end

    private def collect_workspace_symbols(symbols : Array(Outline::Sym), file : String, lines : Array(String), query : String, container : String?, into : Array({String, Int32, String, Int32, Int32, Int32, String?})) : Nil
      symbols.each do |sym|
        if fuzzy_match?(query, sym.name)
          name_line = lines[sym.name_line - 1]? || ""
          start_ch = Lsp.character_of(name_line, sym.name_column)
          end_ch = Lsp.character_of(name_line, sym.name_column + sym.name.size)
          into << {sym.name, sym.kind, file, sym.name_line - 1, start_ch, end_ch, container}
        end
        collect_workspace_symbols(sym.children, file, lines, query, sym.name, into)
      end
    end

    # Subsequence, case-insensitive: `psr` finds `ParseResult`.
    private def fuzzy_match?(query : String, name : String) : Bool
      return true if query.empty?
      qchars = query.downcase.chars
      qi = 0
      name.downcase.each_char do |ch|
        qi += 1 if qi < qchars.size && ch == qchars[qi]
      end
      qi == qchars.size
    end

    # ── Semantic tokens ──────────────────────────────────────────────────

    private def on_semantic_tokens(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      text = text_of(uri)
      lines = text.lines
      toks = Tokens.scan(text)
      toks.sort_by! { |tok| {tok.line, tok.column} }

      respond(id) do |json|
        json.object do
          json.field "data" do
            json.array do
              prev_line = 0
              prev_start = 0
              emitted = false
              toks.each do |tok|
                line0 = tok.line - 1
                next if line0 < 0
                line_text = lines[line0]? || ""
                start_ch = Lsp.character_of(line_text, tok.column)
                length = Lsp.character_of(line_text, tok.column + tok.size) - start_ch
                next if length <= 0
                next if emitted && (line0 < prev_line || (line0 == prev_line && start_ch <= prev_start))
                delta_line = line0 - prev_line
                json.number delta_line
                json.number delta_line.zero? && emitted ? start_ch - prev_start : start_ch
                json.number length
                json.number tok.type
                json.number 0
                prev_line = line0
                prev_start = start_ch
                emitted = true
              end
            end
          end
        end
      end
    end

    # ── Inlay hints ──────────────────────────────────────────────────────

    private def on_inlay_hint(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      path = path_of(uri)
      text = text_of(uri)
      from_line = params["range"]["start"]["line"].as_i + 1
      to_line = params["range"]["end"]["line"].as_i + 1

      hints = @analysis.inlay_hints_at(path, text, overrides_for(path), from_line, to_line)
      return respond_null(id) if hints.empty?

      lines = text.lines
      respond(id) do |json|
        json.array do
          hints.each do |hint|
            line_text = lines[hint.line - 1]? || ""
            json.object do
              json.field "position" do
                json.object do
                  json.field "line", hint.line - 1
                  json.field "character", Lsp.character_of(line_text, hint.column)
                end
              end
              json.field "label", hint.label
              json.field "kind", hint.kind
              json.field "paddingRight", true if hint.kind == InlayVisitor::KIND_PARAMETER
            end
          end
        end
      end
    end

    # ── Code actions ─────────────────────────────────────────────────────

    # The compiler's own suggestion, made clickable: a diagnostic whose
    # message says "Did you mean 'x'?" becomes a quickfix performing the
    # change. No new analysis — the fix was computed when the error was.
    SUGGESTION = /Did you mean '([^']+)'\?/

    private def on_code_action(id : JSON::Any, params : JSON::Any) : Nil
      uri = params["textDocument"]["uri"].as_s
      from = params["range"]["start"]["line"].as_i
      to = params["range"]["end"]["line"].as_i

      actions = (@published[uri]? || [] of {Int32, Int32, Int32, String}).compact_map do |(line0, start_ch, end_ch, message)|
        next unless line0 >= from && line0 <= to && end_ch > start_ch
        next unless match = SUGGESTION.match(message)
        {line0, start_ch, end_ch, message, match[1]}
      end

      respond(id) do |json|
        json.array do
          actions.each do |(line0, start_ch, end_ch, message, suggestion)|
            json.object do
              json.field "title", "Change to '#{suggestion}'"
              json.field "kind", "quickfix"
              json.field "diagnostics" do
                json.array do
                  json.object do
                    json.field "range" { range(json, line0, start_ch, line0, end_ch) }
                    json.field "severity", 1
                    json.field "source", "iyi"
                    json.field "message", message
                  end
                end
              end
              json.field "edit" do
                json.object do
                  json.field "changes" do
                    json.object do
                      json.field uri do
                        json.array do
                          json.object do
                            json.field "range" { range(json, line0, start_ch, line0, end_ch) }
                            json.field "newText", suggestion
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

    # ── Incremental sync ─────────────────────────────────────────────────

    # One contentChange: a range in wire units replaced by new text, or
    # the whole document when the range is absent.
    private def apply_change(text : String, change : JSON::Any) : String
      new_text = change["text"].as_s
      range = change["range"]?
      return new_text unless range

      start_offset = offset_at(text, range["start"]["line"].as_i, range["start"]["character"].as_i)
      end_offset = offset_at(text, range["end"]["line"].as_i, range["end"]["character"].as_i)
      end_offset = start_offset if end_offset < start_offset
      String.build(text.bytesize + new_text.bytesize) do |io|
        io.write text.to_slice[0, start_offset]
        io << new_text
        io.write text.to_slice[end_offset, text.bytesize - end_offset]
      end
    end

    # Byte offset of an LSP position: 0-based line, UTF-16 character.
    private def offset_at(text : String, line : Int32, character : Int32) : Int32
      reader = Char::Reader.new(text)
      current = 0
      while current < line && reader.pos < text.bytesize
        current += 1 if reader.current_char == '\n'
        reader.next_char
      end
      units = 0
      while units < character && reader.pos < text.bytesize
        ch = reader.current_char
        break if ch == '\n'
        units += ch.ord >= 0x10000 ? 2 : 1
        reader.next_char
      end
      reader.pos
    end

    # The workspace root the client named at initialize, for
    # workspace/symbol to glob under.
    private def root_of(params : JSON::Any?) : String?
      return nil unless params
      if folders = params["workspaceFolders"]?.try(&.as_a?)
        if first = folders.first?
          if folder_uri = first["uri"]?.try(&.as_s?)
            return path_of(folder_uri)
          end
        end
      end
      if root_uri = params["rootUri"]?.try(&.as_s?)
        return path_of(root_uri)
      end
      params["rootPath"]?.try(&.as_s?)
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
