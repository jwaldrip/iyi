# iyi: the analysis behind `iyi lsp` — one real compile per question.
#
# Everything here is the front end iyi already has, pointed at editor
# buffers instead of files. The buffer being asked about travels as the
# `Compiler::Source`; every *other* open buffer travels in
# `iyi_file_overrides`, the one hash the resolver and `import_file`
# consult before the disk — so an import finds what the person sees,
# saved or not. R-1 keeps the unit small enough that "recompile the
# module on every keystroke" is not a compromise, it is the design: no
# incremental state, no invalidation story, no answer a build would not
# give.
#
# Locations translate at this boundary and nowhere else: iyi speaks
# 1-indexed lines and 1-indexed codepoint columns (lexer.cr), LSP speaks
# 0-indexed lines and UTF-16 code units. The two converters below are the
# whole treaty.
require "../compiler"
require "../mod/installer"
require "../tools/context"
require "../tools/implementations"

module Iyi::Lsp
  # One diagnostic, in iyi's own units; the server converts at the edge.
  record Diag,
    line : Int32,
    column : Int32,
    size : Int32,
    message : String,
    spec : Array(String)?,
    related : Array({String, Int32, Int32, String})

  class Analysis
    # The last result that type-checked, per document. Hover and
    # definition on a buffer that currently does not compile answer from
    # here — mid-edit is the editor's normal state, and a server that
    # goes mute while you type is a server you turn off.
    @last_good = {} of String => Compiler::Result

    # Compile one buffer as its own entry, front end only. Returns the
    # typed result and no diagnostics, or nil and what went wrong.
    def check(path : String, text : String, overrides : Hash(String, String)) : {Compiler::Result?, Array(Diag)}
      table =
        begin
          Mod::Installer.table_for(File.dirname(path))
        rescue ex : Mod::ModError
          return {nil, [Diag.new(1, 1, 0, ex.message.to_s, nil, [] of {String, Int32, Int32, String})]}
        end

      compiler = Compiler.new
      compiler.prelude = "iyi/prelude"
      compiler.no_codegen = true
      compiler.no_cleanup = true # the visitors read the typed AST after
      compiler.iyi_mod_table = table
      compiler.iyi_file_overrides = overrides
      compiler.stdout = IO::Memory.new
      compiler.iyi_project_root = project_root_of(path, text)
      compiler.stderr = IO::Memory.new

      result = compiler.compile(
        Compiler::Source.new(path, text),
        File.tempname("iyi-lsp", nil))
      @last_good[path] = result
      {result, [] of Diag}
    rescue ex : CodeError
      {nil, [to_diag(ex, path)]}
    rescue ex : Iyi::Error
      {nil, [Diag.new(1, 1, 0, ex.message.to_s, nil, [] of {String, Int32, Int32, String})]}
    end

    # The typed result to answer a cursor question from: this buffer's
    # compile if it passes, the last one that did otherwise.
    def result_for(path : String, text : String, overrides : Hash(String, String)) : Compiler::Result?
      result, _ = check(path, text, overrides)
      result || @last_good[path]?
    end

    def context_at(path : String, text : String, overrides : Hash(String, String), line : Int32, column : Int32) : ContextResult?
      result = result_for(path, text, overrides)
      return nil unless result
      ContextVisitor.new(Location.new(path, line, column)).process(result)
    end

    def implementations_at(path : String, text : String, overrides : Hash(String, String), line : Int32, column : Int32) : ImplementationResult?
      result = result_for(path, text, overrides)
      return nil unless result
      ImplementationsVisitor.new(Location.new(path, line, column)).process(result)
    end

    # IV.6 read backwards: a module's path is its file's path, so a file
    # whose path ends with its own header's path names the project root
    # above both — and opening `<root>/calc/parser.iyi` resolves its
    # `import calc/lexer` the way a build from `<root>` would. A file
    # whose header and path disagree, or that has no header, keeps the
    # entry-dir rule.
    private def project_root_of(path : String, text : String) : String?
      header = nil
      text.each_line do |line|
        line = line.strip
        next if line.empty? || line.starts_with?('#')
        header = line
        break
      end
      return nil unless header && header.starts_with?("module ")
      module_path = header.lchop("module ").strip
      return nil if module_path.empty? || module_path.includes?(' ')
      suffix = "/#{module_path}.iyi"
      return nil unless path.ends_with?(suffix)
      root = path[0, path.size - suffix.size]
      root.empty? ? "/" : root
    end

    # ── CodeError → Diag ─────────────────────────────────────────────────

    # The exception is a chain: outer frames are the trace ("instantiating
    # 'foo'"), the deepest frame is the cause. The diagnostic lands on the
    # deepest frame *in the edited file* — the place the person can fix —
    # with the deepest message, and the other located frames ride along as
    # related information.
    private def to_diag(ex : CodeError, path : String) : Diag
      frames = [] of {String, Int32, Int32, Int32, String}
      cur : CodeError? = ex
      while cur
        line = nil
        col = 0
        size = 0
        case cur
        when SyntaxException
          line = cur.line_number
          col = cur.column_number
          size = cur.size || 0
        when TypeException
          line = cur.line_number
          col = cur.column_number
          size = cur.size
        end
        if line && (msg = cur.message)
          frames << {cur.true_filename, line, col, size, msg}
        end
        cur = cur.is_a?(TypeException) ? cur.inner : nil
      end

      deepest_message = ex.is_a?(TypeException) ? ex.deepest_error_message.to_s : ex.message.to_s

      anchor = frames.reverse.find { |(file, _, _, _, _)| file == path }
      unless anchor
        # Nothing in this file carries a location: the cause lives in an
        # import. Land on line 1 and say where it really is.
        message = deepest_message
        if far = frames.last?
          message += "\n(in #{far[0]}:#{far[1]})"
        end
        return Diag.new(1, 1, 0, message, Iyi.iyi_spec_references(message), [] of {String, Int32, Int32, String})
      end

      message = anchor[4]
      message += "\n#{deepest_message}" unless deepest_message == message

      related = frames.compact_map do |(file, line, col, _, msg)|
        next if file == anchor[0] && line == anchor[1] && col == anchor[2]
        {file, line, col, msg}
      end

      Diag.new(anchor[1], anchor[2], anchor[3], message, Iyi.iyi_spec_references(message), related)
    end
  end

  # ── The location treaty: iyi columns ↔ LSP characters ─────────────────

  # LSP 0-indexed UTF-16 character → iyi 1-indexed codepoint column.
  def self.column_of(line_text : String, character : Int32) : Int32
    units = 0
    codepoints = 0
    line_text.each_char do |ch|
      break if units >= character
      units += ch.ord >= 0x10000 ? 2 : 1
      codepoints += 1
    end
    codepoints + 1
  end

  # iyi 1-indexed codepoint column → LSP 0-indexed UTF-16 character.
  def self.character_of(line_text : String, column : Int32) : Int32
    target = column - 1
    units = 0
    line_text.each_char_with_index do |ch, index|
      break if index >= target
      units += ch.ord >= 0x10000 ? 2 : 1
    end
    units
  end
end
