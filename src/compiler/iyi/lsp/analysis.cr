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
require "./references"

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

    # One entry's contribution to a references answer. The target names
    # the cursor's file and position; the entry is whichever open
    # document's program we are searching — under R-1 a def's callers
    # live in the *consumers'* compiles, so the server asks this once per
    # open document and merges.
    def references_at(entry_path : String, entry_text : String, overrides : Hash(String, String), target : Location) : ReferencesVisitor?
      result = result_for(entry_path, entry_text, overrides)
      return nil unless result
      visitor = ReferencesVisitor.new(target)
      visitor.process(result) ? visitor : nil
    end

    # Completion: the names the typed graph offers at this cursor. With a
    # receiver, its type's methods, ancestors included; bare, the scope's
    # variables plus `self`'s methods. Items are {label, detail, kind} in
    # LSP's own kind numbers. The buffer mid-word rarely compiles, which
    # is why `result_for` falling back to the last good result is not a
    # convenience here but the feature: completion is a question about
    # the program as it last held together.
    def completion_at(path : String, text : String, overrides : Hash(String, String), line : Int32, column : Int32, receiver : String?) : Array({String, String, Int32})
      result = result_for(path, text, overrides)
      return [] of {String, String, Int32} unless result

      contexts = ContextVisitor.new(Location.new(path, line, column))
        .process(result).contexts
      return [] of {String, String, Int32} unless contexts

      scope = {} of String => Type
      contexts.each { |ctx| ctx.each { |name, type| scope[name] ||= type } }

      if receiver
        type = scope[receiver]?
        return [] of {String, String, Int32} unless type
        methods_of(type, kind: 2) # Method
      else
        items = scope.compact_map do |name, type|
          next if name.includes?(' ') || name.includes?('(')            # call keys
          {name, PrettyTypeNameJsonConverter.pretty_type_name(type), 6} # Variable
        end
        if self_type = scope["self"]?
          items.concat methods_of(self_type, kind: 3) # Function
        end
        items
      end
    end

    # One entry per name, nearest ancestor wins — the same order a call
    # resolves in. `initialize` is `new`'s business and compiler-internal
    # names are nobody's.
    private def methods_of(type : Type, kind : Int32) : Array({String, String, Int32})
      members =
        if type.is_a?(UnionType)
          type.union_types
        else
          [type] of Type
        end

      seen = {} of String => String
      members.each do |member|
        ([member] + member.ancestors).each do |owner|
          owner.defs.try &.each do |name, entries|
            next if name == "initialize" || name.starts_with?("__")
            next if seen.has_key?(name)
            item = entries.first?
            next unless item
            a_def = item.def
            next if a_def.visibility.private?
            seen[name] = signature_of(a_def)
          end
        end
      end
      seen.map { |name, detail| {name, detail, kind} }
    end

    # The signature as the author wrote it: arguments with their
    # restrictions, the return type if stated. Bodies stay home.
    private def signature_of(a_def : Def) : String
      String.build do |io|
        io << a_def.name
        unless a_def.args.empty?
          io << '('
          a_def.args.each_with_index do |arg, index|
            io << ", " unless index.zero?
            arg.to_s(io)
          end
          io << ')'
        end
        if return_type = a_def.return_type
          io << " : "
          return_type.to_s(io)
        end
      end
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
