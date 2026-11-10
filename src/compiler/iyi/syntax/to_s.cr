require "./ast"
require "./visitor"

module Iyi
  class ASTNode
    def to_s(io : IO, macro_expansion_pragmas = nil, emit_doc = false, emit_location_pragmas : Bool = false,
             diagnostic_anchors : Array(DiagnosticAnchor)? = nil,
             diagnostic_emissions : Array(DiagnosticMacroAnchor)? = nil,
             diagnostic_generated_text : Array(DiagnosticGeneratedText)? = nil,
             diagnostic_emitter : DiagnosticOrigin? = nil,
             diagnostic_name_fragments : Array(DiagnosticMacroNameFragment)? = nil) : Nil
      visitor = ToSVisitor.new(io, macro_expansion_pragmas: macro_expansion_pragmas, emit_doc: emit_doc,
        emit_location_pragmas: emit_location_pragmas, diagnostic_anchors: diagnostic_anchors,
        diagnostic_emissions: diagnostic_emissions, diagnostic_generated_text: diagnostic_generated_text,
        diagnostic_emitter: diagnostic_emitter, diagnostic_name_fragments: diagnostic_name_fragments)
      self.accept visitor
    end
  end

  class ToSVisitor < Visitor
    @str : IO
    @macro_expansion_pragmas : Hash(Int32, Array(Lexer::LocPragma))?
    @current_arg_type : DefArgType = :none
    @inside_enum_member = false

    # Represents the root level `Expressions` instance within a `MacroExpression`.
    @root_level_macro_expressions : Expressions? = nil

    # Inside a comma-separated list of parameters or args, this becomes true and
    # the outermost pair of parentheses are removed from type restrictions that
    # are `ProcNotation` nodes, so `foo(x : (T, U -> V), W)` becomes
    # `foo(x : T, U -> V, W)`. This is used by defs, lib funs, and calls to deal
    # with the parsing rules for `->`. See #11966 and #14216 for more details.
    getter? drop_parens_for_proc_notation = false

    private enum DefArgType
      NONE
      SPLAT
      DOUBLE_SPLAT
      BLOCK_ARG
    end

    def initialize(@str = IO::Memory.new, @macro_expansion_pragmas = nil, @emit_doc = false, @emit_location_pragmas : Bool = false,
                   @diagnostic_anchors : Array(DiagnosticAnchor)? = nil,
                   @diagnostic_emissions : Array(DiagnosticMacroAnchor)? = nil,
                   @diagnostic_generated_text : Array(DiagnosticGeneratedText)? = nil,
                   @diagnostic_emitter : DiagnosticOrigin? = nil,
                   @diagnostic_name_fragments : Array(DiagnosticMacroNameFragment)? = nil)
      @indent = 0
      @inside_macro = 0
    end

    private def diagnostic_anchor(node : ASTNode, kind : String, role : String, name_splice = false) : Nil
      if anchors = @diagnostic_anchors
        slots = kind == "Call" && role == "method" ? node.diagnostic_name_slots : ({} of DiagnosticNameSlot => Array(DiagnosticNameValue))
        anchors << DiagnosticAnchor.new(@str.pos.to_i32, kind, role, node.diagnostic_origin, slots)
      end
      if @diagnostic_emissions && !(name_splice && @diagnostic_name_fragments)
        raise ArgumentError.new("structural macro anchor lacks a measured writer extent for #{kind}:#{role}")
      end
    end

    private def diagnostic_anchor(node : ASTNode, kind : String, role : String, &)
      if anchors = @diagnostic_anchors
        slots = kind == "Call" && role == "method" ? node.diagnostic_name_slots : ({} of DiagnosticNameSlot => Array(DiagnosticNameValue))
        anchors << DiagnosticAnchor.new(@str.pos.to_i32, kind, role, node.diagnostic_origin, slots)
      end
      start = @str.pos.to_i32 if @diagnostic_emissions
      yield
      if emissions = @diagnostic_emissions
        finish = @str.pos.to_i32
        first = start.not_nil!
        raise ArgumentError.new("empty structural macro anchor") unless finish > first
        case node.diagnostic_macro_lineage
        when .preserved?
          origin = node.diagnostic_origin || raise ArgumentError.new("preserved macro node lacks origin")
          raise ArgumentError.new("preserved macro node origin mismatch") unless origin.valid_for_anchor?(kind, role)
          emissions << DiagnosticMacroAnchor.new(first, finish, kind, role, @diagnostic_emitter, origin, nil)
        when .constructed?
          emissions << DiagnosticMacroAnchor.new(first, finish, kind, role, @diagnostic_emitter, nil, DiagnosticMacroProducer::ConstructedAst)
        else
          raise ArgumentError.new("unclassified macro node at #{first} for #{kind}:#{role}")
        end
      end
    end

    protected def diagnostic_raw(node : ASTNode, producer : DiagnosticMacroProducer, &) : Nil
      start = @str.pos.to_i32 if @diagnostic_generated_text
      yield
      if generated = @diagnostic_generated_text
        finish = @str.pos.to_i32
        generated << DiagnosticGeneratedText.new(start.not_nil!, finish, @diagnostic_emitter, producer) if finish > start.not_nil!
      end
    end

    private def diagnostic_name(node : ASTNode, text : String, context : String,
                                slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary),
                                artifact_anchor = true) : Nil
      unless @diagnostic_name_fragments || @diagnostic_anchors
        @str << text
        return
      end
      tokens = node.diagnostic_name_slots[slot]?
      if tokens && !tokens.empty?
        unless tokens.join(&.rendered_text) == text
          raise ArgumentError.new("diagnostic name was renamed without a recorded projection")
        end
        if context == "macro_name"
          valid = if tokens.size == 1
                    value = tokens.first.rendered_text
                    value != "=" && (!value.ends_with?("=") || DiagnosticSourceNameToken::MACRO_OPERATORS.includes?(value))
                  elsif tokens.size == 2
                    first = tokens[0].rendered_text
                    tokens[1].rendered_text == "=" && !first.ends_with?("?") && !first.ends_with?("!") &&
                      (DiagnosticSourceNameToken.valid_token?("IDENT", first, "Crystal", "macro_name") ||
                       DiagnosticSourceNameToken.valid_token?("CONST", first, "Crystal", "macro_name"))
                  else
                    false
                  end
          raise ArgumentError.new("invalid complete macro name") unless valid
        end
        tokens.each do |token|
          start = @str.pos.to_i32
          if (anchors = @diagnostic_anchors) && artifact_anchor
            origin = token.artifact_origin
            if origin.valid_for_anchor?("Name", context)
              anchors << DiagnosticAnchor.new(start, "Name", context, origin, {slot => [token]})
            elsif origin.valid_for_anchor?("Call", "method")
              anchors << DiagnosticAnchor.new(start, "Call", "method", origin, {slot => [token]})
            else
              raise ArgumentError.new("diagnostic name lacks an artifact anchor for #{context}")
            end
          end
          @str << token.rendered_text
          @diagnostic_name_fragments.try &.<< DiagnosticMacroNameFragment.new(start, @str.pos.to_i32, @diagnostic_emitter, token)
        end
      elsif node.diagnostic_macro_lineage.constructed?
        diagnostic_raw(node, DiagnosticMacroProducer::ConstructedAst) { @str << text }
      else
        raise ArgumentError.new("name lacks token evidence for #{context}")
      end
    end

    private def diagnostic_named_entry(node : ASTNode, name : String, slot : DiagnosticNameSlot) : Nil
      if !@diagnostic_name_fragments && !@diagnostic_anchors
        visit_named_arg_name(name)
      elsif node.diagnostic_name_slots[slot]?
        rendered = String.build { |io| Symbol.quote_for_named_argument(io, name) }
        raise ArgumentError.new("quoted named entry projection is not recorded") unless rendered == name
        diagnostic_name(node, name, "named_entry", slot)
      elsif node.diagnostic_macro_lineage.constructed?
        diagnostic_raw(node, DiagnosticMacroProducer::ConstructedAst) { visit_named_arg_name(name) }
      else
        raise ArgumentError.new("named entry lacks token evidence")
      end
    end

    private def diagnostic_external_name(node : Arg) : Nil
      diagnostic_named_entry(node, node.external_name, DiagnosticNameSlot.new(DiagnosticNameSlotKind::ExternalName))
    end

    private def diagnostic_arg_name(node : Arg, name : String, enum_member : Bool) : Nil
      unless @diagnostic_name_fragments || @diagnostic_anchors
        @str << name
        return
      end
      slots = node.diagnostic_name_slots
      primary = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
      member = DiagnosticNameSlot.new(DiagnosticNameSlotKind::EnumMember)
      if slots.has_key?(primary) && slots.has_key?(member)
        raise ArgumentError.new("conflicting enum member and parameter names")
      end
      if slots.has_key?(member) || enum_member
        diagnostic_name(node, name, "enum_member", member)
      else
        diagnostic_name(node, name, "parameter", primary)
      end
    end

    def visit_any(node)
      if @emit_doc && (doc = node.doc) && !doc.empty?
        doc.each_line(chomp: true) do |line|
          @str << "# "
          @str << line
          newline
          append_indent
        end
      end

      if (macro_expansion_pragmas = @macro_expansion_pragmas) && (loc = node.location) && (filename = loc.filename).is_a?(String)
        pragmas = macro_expansion_pragmas[@str.pos.to_i32] ||= [] of Lexer::LocPragma
        pragmas << Lexer::LocSetPragma.new(filename, loc.line_number, loc.column_number, loc.artifact)
      end

      true
    end

    private def write_extra_newlines(first_node_location : Location?, second_node_location : Location?) : Nil
      if first_node_location && second_node_location
        # Only write the "extra" newlines. I.e. If there are more than one. The first newline is handled directly via the Expressions visitor.
        ((second_node_location.line_number - 1) - first_node_location.line_number).times do
          newline
        end
      end
    end

    def visit(node : Nop)
      false
    end

    def visit(node : BoolLiteral)
      @str << (node.value ? "true" : "false")
      false
    end

    def visit(node : NumberLiteral)
      @str << node.value

      if needs_suffix?(node)
        @str << '_'
        @str << node.kind.to_s
      end

      false
    end

    def needs_suffix?(node : NumberLiteral)
      case node.kind
      when .i32?
        false
      when .f64?
        # If there's no '.' nor 'e', for example in `1_f64`,
        # we need to include it (#3315)
        node.value.each_char do |char|
          return false if char.in?('.', 'e')
        end

        true
      else
        true
      end
    end

    def visit(node : CharLiteral)
      node.value.inspect(@str)
      false
    end

    def visit(node : SymbolLiteral)
      visit_symbol_literal_value node.value
      false
    end

    def visit_symbol_literal_value(value : String)
      @str << ':'
      if Symbol.needs_quotes?(value)
        value.inspect(@str)
      else
        value.to_s(@str)
      end
    end

    def visit(node : StringLiteral)
      node.value.inspect(@str)
      false
    end

    def visit(node : StringInterpolation)
      diagnostic_anchor(node, "Literal", "interpolation") { @str << '"' }
      visit_interpolation node, &.inspect_unquoted
      @str << '"'
      false
    end

    def visit_interpolation(node, &)
      node.expressions.chunks(&.is_a?(StringLiteral)).each do |(is_string, exps)|
        if is_string
          value = exps.join(&.as(StringLiteral).value)
          @str << yield value
        else
          exps.each do |exp|
            @str << "\#{"
            # iyi: a lowering can leave several expressions where one was
            # written: `#{half(x).or(-1)}` is a temporary and an `if` once
            # normalized, and that is the text a body travelling in a
            # `.iyimod` is (IV.1g). An interpolation reads one expression, so
            # unwrapped the consumer stopped on "Unterminated string
            # interpolation" in a module that had compiled; parenthesized
            # it is one again.
            if exp.is_a?(Expressions) && !exp.keyword.paren? && exp.expressions.size > 1
              @str << '('
              exp.accept(self)
              @str << ')'
            else
              exp.accept(self)
            end
            @str << '}'
          end
        end
      end
    end

    def visit(node : ArrayLiteral)
      diagnostic_anchor(node, "Literal", "array") if node.name
      name = node.name
      if name
        name.accept self
        @str << " {"
      else
        diagnostic_anchor(node, "Literal", "array") { @str << '[' }
      end

      node.elements.join(@str, ", ") { |element| accept_as_expression element }

      if name
        @str << '}'
      else
        @str << ']'
      end

      if of = node.of
        @str << " of "
        of.accept self
      end
      false
    end

    def visit(node : HashLiteral)
      diagnostic_anchor(node, "Literal", "hash") if node.name
      if name = node.name
        name.accept self
        @str << ' '
      end

      space = false
      if node.name
        @str << '{'
      else
        diagnostic_anchor(node, "Literal", "hash") { @str << '{' }
      end

      node.entries.each_with_index do |entry, i|
        @str << ", " if i > 0

        space = i == 0 && entry.key.is_a?(TupleLiteral) || entry.key.is_a?(NamedTupleLiteral) || entry.key.is_a?(HashLiteral)
        @str << ' ' if space

        accept_as_expression entry.key
        @str << " => "
        accept_as_expression entry.value
      end

      @str << ' ' if space
      @str << '}'
      if of = node.of
        @str << " of "
        of.key.accept self
        @str << " => "
        of.value.accept self
      end
      false
    end

    def visit(node : NamedTupleLiteral)
      # short-circuit to handle empty named tuple context
      if node.entries.empty?
        start = @str.pos.to_i32 if @diagnostic_emissions || @diagnostic_generated_text
        @str << "::NamedTuple."
        method_start = @str.pos.to_i32 if @diagnostic_emissions
        @str << "new"
        if emissions = @diagnostic_emissions
          emissions << DiagnosticMacroAnchor.new(method_start.not_nil!, @str.pos.to_i32, "Call", "method", @diagnostic_emitter, nil, DiagnosticMacroProducer::EmptyNamedTupleProjection)
        end
        if generated = @diagnostic_generated_text
          generated << DiagnosticGeneratedText.new(start.not_nil!, @str.pos.to_i32, @diagnostic_emitter, DiagnosticMacroProducer::EmptyNamedTupleProjection)
        end
        return false
      end

      @str << '{'

      # A node starts multiline when its starting brace is on a different line than the staring line of it's first entry
      start_multiline = (start_loc = node.location) && (first_entry_loc = node.entries.first?.try &.value.location) && first_entry_loc.line_number > start_loc.line_number

      # and similarly ends multiline if its last entry's end location is on a different line than its ending brace
      end_multiline = (last_entry_loc = node.entries.last?.try &.value.end_location) && (end_loc = node.end_location) && end_loc.line_number > last_entry_loc.line_number

      last_entry = node.entries.first

      if start_multiline
        newline
        @indent += 1
        append_indent
      end

      node.entries.each_with_index do |entry, idx|
        write_extra_newlines (last_entry.value || entry.value).end_location, entry.value.location

        if (current_entry_loc = entry.value.location) && (last_entry_loc = last_entry.value.location) && current_entry_loc.line_number > last_entry_loc.line_number
          newline

          # If the node is not starting multiline, explicitly enable it once there is a line break to ensure additional values are indented properly
          unless start_multiline
            start_multiline = true
            @indent += 1
          end

          append_indent
        elsif !idx.zero?
          @str << ' '
        end

        diagnostic_named_entry(node, entry.key, DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry, idx))
        @str << ": "
        accept_as_expression entry.value

        last_entry = entry

        @str << ',' unless idx == node.entries.size - 1
      end

      @indent -= 1 if start_multiline

      if end_multiline
        @str << ','
        newline
        append_indent
      end

      @str << '}'
      false
    end

    def visit(node : NilLiteral)
      @str << "nil"
      false
    end

    def visit(node : Expressions)
      is_multiline = false

      case node.keyword
      in .paren?
        # Handled via dedicated #in_parenthesis call below
        is_multiline = (loc = node.location) && (first_loc = node.expressions.first?.try &.location) && (first_loc.line_number > loc.line_number)
        append_indent if is_multiline
      in .begin?
        @str << "begin"
        @indent += 1
        newline
      in .none?
        # Not a special condition
      end

      in_parenthesis node.keyword.paren?, is_multiline do
        if @inside_macro > 0
          node.expressions.each &.accept self
        else
          last_node = nil

          node.expressions.each_with_index do |exp, i|
            unless exp.nop?
              write_extra_newlines (last_node || exp).end_location, exp.location

              append_indent unless node.keyword.paren? && i == 0
              exp.accept self

              if (root = @root_level_macro_expressions) && root.same?(node) && i == node.expressions.size - 1
                # Do not add a trailing newline after the last node in the root `Expressions` within a `MacroExpression`.
                # This is handled by the `MacroExpression` logic.
              elsif !(node.keyword.paren? && i == node.expressions.size - 1)
                newline
              end

              last_node = exp
            end
          end
        end
      end

      case node.keyword
      in .paren?
        # Handled via dedicated #in_parenthesis call above
      in .begin?
        @indent -= 1
        append_indent
        @str << "end"
      in .none?
        # Not a special condition
      end

      false
    end

    private def emit_loc_pragma(for location : Location?) : Nil
      if @emit_location_pragmas && (loc = location) && (filename = loc.filename).is_a?(String)
        @str << %(#<loc:"#{filename}",#{loc.line_number},#{loc.column_number}>)
      end
    end

    def visit(node : If)
      if node.ternary?
        accept_as_expression node.cond
        @str << " ? "
        accept_as_expression node.then
        @str << " : "
        accept_as_expression node.else
        return false
      end

      self.emit_loc_pragma node.location

      while true
        @str << "if "
        accept_as_expression node.cond
        newline

        self.emit_loc_pragma node.then.location

        accept_with_indent(node.then)
        append_indent

        # combine `else if` into `elsif` (does not apply to `unless` or `? :`)
        if (else_node = node.else).is_a?(If) && !else_node.ternary?
          @str << "els"
          node = else_node
        else
          break
        end
      end

      unless else_node.nop?
        @str << "else"
        newline

        self.emit_loc_pragma node.else.location

        accept_with_indent(node.else)
        append_indent
      end

      self.emit_loc_pragma node.end_location

      @str << "end"
      false
    end

    def visit(node : Unless)
      self.emit_loc_pragma node.location

      @str << "unless "
      accept_as_expression node.cond
      newline

      self.emit_loc_pragma node.then.location

      accept_with_indent(node.then)
      unless node.else.nop?
        append_indent
        @str << "else"
        newline

        self.emit_loc_pragma node.else.location

        accept_with_indent(node.else)
      end
      append_indent

      self.emit_loc_pragma node.end_location

      @str << "end"

      false
    end

    def visit(node : ClassDef)
      if node.abstract?
        @str << "abstract "
      end
      diagnostic_anchor(node, "ClassDef", "keyword") { @str << (node.struct? ? "struct" : "class") }
      @str << ' '
      node.name.accept self
      if type_vars = node.type_vars
        @str << '('
        type_vars.each_with_index do |type_var, i|
          @str << ", " if i > 0
          @str << '*' if node.splat_index == i
          diagnostic_name(node, type_var.to_s, "type_parameter", DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, i))
        end
        @str << ')'
      end
      if superclass = node.superclass
        @str << " < "
        superclass.accept self
      end
      newline
      accept_with_indent(node.body)

      append_indent
      @str << "end"
      false
    end

    def visit(node : ModuleHeader)
      @str << "module " << node.path.join('/')
      false
    end

    def visit(node : ImportDecl)
      @str << "pub " if node.exported
      @str << "import " << node.path.join('/')
      if node.glob?
        @str << "::*"
      elsif names = node.names
        @str << "::{" << names.join(", ") << '}'
      end
      false
    end

    # The scope an `import x::{a}` makes beside it: the import says it, and
    # there is no source of its own to write.
    def visit(node : UsingDecl)
      false
    end

    def visit(node : TraitDef)
      @str << "pub " if node.exported?
      @str << "trait "
      node.name.accept self
      if type_vars = node.type_vars
        @str << '('
        type_vars.each_with_index do |name, i|
          @str << ", " if i > 0
          diagnostic_name(node, name.to_s, "type_parameter", DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, i))
        end
        @str << ')'
      end
      if supertraits = node.supertraits
        @str << " : "
        supertraits.each_with_index do |supertrait, i|
          @str << ", " if i > 0
          supertrait.accept self
        end
      end
      newline
      accept_with_indent(node.body)
      append_indent
      @str << "end"
      false
    end

    def visit(node : Propagate)
      node.exp.accept self
      @str << '!'
      false
    end

    def visit(node : Defer)
      diagnostic_anchor(node, "Defer", "keyword") { @str << "defer" }
      @str << ' '
      node.exp.accept self
      false
    end

    def visit(node : Recover)
      node.exp.accept self
      if default = node.default
        @str << '.'
        diagnostic_anchor(node, "Call", "method") { @str << "or" }
        @str << '('
        default.accept self
        @str << ')'
      else
        @str << '.'
        diagnostic_anchor(node, "Call", "method") { @str << "or_panic" }
      end
      false
    end

    def visit(node : AssocTypeDecl)
      @str << "type " << node.name
      if value = node.value
        @str << " = "
        value.accept self
      end
      false
    end

    def visit(node : ImplDef)
      @str << "impl "
      node.trait.accept self
      @str << " for "
      node.target.accept self
      if type_vars = node.type_vars
        @str << " forall "
        type_vars.each_with_index do |name, i|
          @str << ", " if i > 0
          diagnostic_name(node, name.to_s, "type_parameter", DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, i))
        end
      end
      newline
      accept_with_indent(node.body)
      append_indent
      @str << "end"
      false
    end

    def visit(node : ModuleDef)
      @str << "module "
      node.name.accept self
      if type_vars = node.type_vars
        @str << '('
        type_vars.each_with_index do |type_var, i|
          @str << ", " if i > 0
          @str << '*' if node.splat_index == i
          diagnostic_name(node, type_var.to_s, "type_parameter", DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, i))
        end
        @str << ')'
      end
      newline
      accept_with_indent(node.body)

      append_indent
      @str << "end"
      false
    end

    def visit(node : AnnotationDef)
      @str << "annotation "
      node.name.accept self
      newline
      append_indent
      @str << "end"
      false
    end

    def visit(node : Call)
      visit_call node
    end

    # Related: `Token::Kind#unary_operator?`
    UNARY_OPERATORS = {"+", "-", "~", "&+", "&-"}

    def visit_call(node, ignore_obj = false)
      if node.name == "`"
        visit_backtick(node.args[0], node)
        return false
      end

      node_obj = ignore_obj ? nil : node.obj
      block = node.block

      short_block_call = nil
      short_block = nil
      if block
        # Check if this is foo &.bar
        first_block_arg = block.args.first?
        if first_block_arg && block.args.size == 1 && block.args.first.name.starts_with?("__arg")
          block_body = block.body
          if block_body.is_a?(Call)
            block_obj = block_body.obj
            if block_obj.is_a?(Var) && block_obj.name == first_block_arg.name
              short_block_call = block_body
              short_block = block
              block = nil
            end
          end
        end
      end

      need_parens = need_parens(node_obj)
      is_multiline = false

      @str << "::" if node.global?
      if node_obj.is_a?(ImplicitObj)
        @str << '.'
        node_obj = nil
      end

      if node_obj && node.name.in?("[]", "[]?") && !block
        in_parenthesis(need_parens, node_obj)
        diagnostic_anchor(node, "Call", "method") { @str << "[" }
        visit_args(node)

        if short_block_call
          @str << ", " if node.args.present? || node.named_args
          diagnostic_anchor(short_block.not_nil!, "Block", "ampersand") { @str << "&." }
          visit_call short_block_call, ignore_obj: true
        end

        if node.name == "[]"
          @str << "]"
        else
          @str << "]?"
        end
      elsif node_obj && node.name == "[]=" && !node.args.empty? && !block
        in_parenthesis(need_parens, node_obj)
        diagnostic_anchor(node, "Call", "method") { @str << "[" }
        visit_args(node, exclude_last: true)

        if short_block_call
          @str << ", " if node.args.size > 1 || node.named_args
          diagnostic_anchor(short_block.not_nil!, "Block", "ampersand") { @str << "&." }
          visit_call short_block_call, ignore_obj: true
        end

        @str << "] = "
        accept_as_expression node.args.last
      elsif node_obj && node.name.in?(UNARY_OPERATORS) && node.args.empty? && !node.named_args && !node.block_arg && !block && !short_block_call
        diagnostic_anchor(node, "Call", "method") { @str << node.name }
        in_parenthesis(need_parens, node_obj)
      elsif node_obj && !Lexer.ident?(node.name) && node.name != "~" && node.args.size == 1 && !node.named_args && !node.block_arg && !block && !short_block_call
        in_parenthesis(need_parens, node_obj)

        arg = node.args[0]
        @str << ' '
        diagnostic_anchor(node, "Call", "method") { @str << node.name }
        @str << ' '
        in_parenthesis(need_parens(arg), arg)
      else
        if node_obj
          # A call is multiline if the call's name is on a diff line than the obj it's being called on.
          is_multiline = (node_obj_end_loc = node_obj.end_location) && (name_loc = node.name_end_location) && (name_loc.line_number > node_obj_end_loc.line_number)

          in_parenthesis(need_parens, node_obj)

          if is_multiline
            newline
            @indent += 1
            append_indent
          end

          @str << '.'
        end
        if Lexer.setter?(node.name)
          diagnostic_anchor(node, "Call", "method", name_splice: true)
          diagnostic_name(node, node.name.rchop, "method_name", artifact_anchor: false)
          @str << " = "
          node.args.join(@str, ", ") { |arg| accept_as_expression arg }
        else
          diagnostic_anchor(node, "Call", "method", name_splice: true)
          diagnostic_name(node, node.name, "method_name", artifact_anchor: false)
          in_parenthesis(node.has_parentheses? || !node.args.empty? || node.block_arg || node.named_args || short_block_call) do
            visit_args(node)

            if short_block_call
              @str << ", " if node.args.present? || node.named_args
              diagnostic_anchor(short_block.not_nil!, "Block", "ampersand") { @str << "&." }
              visit_call short_block_call, ignore_obj: true
            end
          end
        end
      end

      if block
        @str << ' '
        block.accept self
      end

      @indent -= 1 if is_multiline

      false
    end

    private def visit_args(node, exclude_last = false)
      printed_arg = false
      node.args.each_with_index do |arg, i|
        break if exclude_last && i == node.args.size - 1

        @str << ", " if printed_arg
        drop_parens_for_proc_notation(arg) { |each| accept_as_expression(each) }
        printed_arg = true
      end
      if named_args = node.named_args
        named_args.each do |named_arg|
          @str << ", " if printed_arg
          drop_parens_for_proc_notation(named_arg, &.accept(self))
          printed_arg = true
        end
      end
      if block_arg = node.block_arg
        @str << ", " if printed_arg
        @str << '&'
        drop_parens_for_proc_notation(block_arg) { |each| accept_as_expression(each) }
      end
    end

    private def need_parens(obj)
      case obj
      when Call
        case obj.args.size
        when 0
          !Lexer.ident?(obj.name)
        else
          case obj.name
          when "[]", "[]?", "<", "<=", ">", ">="
            false
          else
            true
          end
        end
      when Not
        case exp = obj.exp
        when Call
          exp.obj.nil?
        else
          !obj.exp.is_a? Call
        end
      when Var, NilLiteral, BoolLiteral, CharLiteral, NumberLiteral, StringLiteral,
           StringInterpolation, Path, Generic, InstanceVar, ClassVar, Global,
           ImplicitObj, TupleLiteral, NamedTupleLiteral, IsA
        false
      when ArrayLiteral
        !!obj.of
      when HashLiteral
        !!obj.of
      else
        true
      end
    end

    def in_parenthesis(need_parens, is_multiline = false, &)
      @str << '(' if need_parens

      if is_multiline
        newline
        @indent += 1
        append_indent
      end

      yield

      if is_multiline
        newline
        @indent -= 1
        append_indent
      end

      @str << ')' if need_parens
    end

    def in_parenthesis(need_parens, node, is_multiline = false)
      in_parenthesis(need_parens, is_multiline) do
        if node.is_a?(Expressions) && node.expressions.size == 1
          node.expressions.first.accept self
        elsif need_parens && node.is_a?(Expressions) && node.keyword.none?
          # The statements one after another inside the parentheses, the way
          # a `(a = 1; a)` the parser kept prints, rather than through the
          # `Expressions` visitor, which ends every statement with a newline
          # and would leave the `)` alone on a line of its own.
          node.expressions.reject(&.nop?).each_with_index do |exp, i|
            if i > 0
              newline
              append_indent
            end
            exp.accept self
          end
        else
          node.accept self
        end
      end
    end

    # iyi: a node printed where the parser reads an expression — an argument,
    # a literal's element, a condition, an assigned value — rather than a
    # statement. The text is source a later build parses again: a travelling
    # body crosses an `.iyimod` as `Def#body.to_s` (SPEC.md IV.1g), printed
    # after the normalizer has expanded it. `twice(parse(text).or_panic, t)`
    # crossed as `twice(__temp_6 = parse(text)` and an `if` on the next line,
    # because `.or_panic` expands to an assignment and an `if` held in one
    # bare `Expressions`, and the consumer stopped at "expecting token ')',
    # not 'if'". Those positions are parsed by `parse_op_assign_no_control`,
    # which takes one expression — `if`, `case`, `begin`, `while` and an
    # assignment are all expressions and stand bare there — but neither a
    # sequence of statements, nor `return`/`break`/`next`, nor `a, b = 1, 2`,
    # whose commas would be read as the list's own. Those are parenthesized —
    # unless one of the statements is `a, b = 1, 2`, which a parenthesized
    # expression does not read either ("unterminated parenthesized
    # expression"); `begin` reads statements, that one included.
    private def accept_as_expression(node : ASTNode) : Nil
      unless (node.is_a?(Expressions) && node.keyword.none?) || node.is_a?(MultiAssign | Return | Break | Next)
        node.accept self
        return
      end

      statements = statements_of(node)
      if statements.any?(MultiAssign)
        Expressions.new(statements).tap { |exps| exps.keyword = :begin }.accept self
      elsif statements.size > 1 || statements.first?.is_a?(Return | Break | Next)
        in_parenthesis(true, Expressions.new(statements))
      elsif first = statements.first?
        first.accept self
      else
        # Nothing but `Nop`s: `()`, which is `nil` wherever it is read.
        @str << "()"
      end
    end

    # The statements a keyword-less `Expressions` holds, nested ones
    # flattened and `Nop`s left out; anything else is its own one statement.
    private def statements_of(node : ASTNode) : Array(ASTNode)
      return [node] of ASTNode unless node.is_a?(Expressions) && node.keyword.none?
      node.expressions.flat_map { |exp| exp.nop? ? [] of ASTNode : statements_of(exp) }
    end

    def visit(node : NamedArgument)
      diagnostic_named_entry(node, node.name, DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry))
      @str << ": "
      accept_as_expression node.value
      false
    end

    def visit_backtick(exp, call : Call? = nil)
      if call
        diagnostic_anchor(call, "Call", "method") { @str << '`' }
      else
        @str << '`'
      end
      case exp
      when StringLiteral
        @str << exp.value.inspect_unquoted.gsub('`', "\\`")
      when StringInterpolation
        diagnostic_anchor(exp, "Literal", "interpolation")
        visit_interpolation exp, &.inspect_unquoted.gsub('`', "\\`")
      else
        # This branch can be reached after the literal expander has expanded
        # `StringLiteral` nodes to a call to `::String.interpolation` which means
        # `exp` is a `Call`.

        @str << "\#{"
        exp.accept(self)
        @str << "}"
      end
      @str << '`'
      false
    end

    def visit(node : Assign)
      # iyi: a module's top level travels as source, so `pub` on a constant has
      # to be in the text (R-2, SPEC.md IV.2).
      target = node.target
      @str << "pub " if target.is_a?(Path) && target.exported?
      diagnostic_anchor(node, "Assign", "constant") if target.is_a?(Path)
      node.target.accept self
      @str << " = "

      accept_as_expression node.value

      false
    end

    def visit(node : OpAssign)
      node.target.accept self
      @str << ' '
      diagnostic_anchor(node, "Call", "method") { @str << node.op << '=' }
      @str << ' '
      accept_as_expression node.value
      false
    end

    def visit(node : MultiAssign)
      diagnostic_anchor(node, "Literal", "multiassign")
      node.targets.join(@str, ", ") do |target|
        target.accept self
      end
      @str << " = "
      node.values.join(@str, ", ") { |value| accept_as_expression value }
      false
    end

    def visit(node : While)
      visit_while_or_until node, "while"
    end

    def visit(node : Until)
      visit_while_or_until node, "until"
    end

    def visit_while_or_until(node, name)
      @str << name
      @str << ' '
      accept_as_expression node.cond
      newline
      accept_with_indent(node.body)
      append_indent
      @str << "end"
      false
    end

    def visit(node : Out)
      @str << "out "
      node.exp.accept self
      false
    end


    def visit(node : Var)
      if node.name == "_" || node.name.empty?
        @str << node.name
      elsif node.name == "$~" || node.name == "$?"
        diagnostic_name(node, node.name, "special_global")
      else
        diagnostic_name(node, node.name, "local_reference")
      end
      false
    end

    def visit(node : ProcLiteral)
      diagnostic_anchor(node, "ProcLiteral", "arrow") { @str << "->" }
      if node.def.args.size > 0
        @str << '('
        node.def.args.join(@str, ", ", &.accept self)
        @str << ')'
      end
      if return_type = node.def.return_type
        @str << " : "
        return_type.accept self
      end
      @str << " do"
      newline
      accept_with_indent(node.def.body)
      append_indent
      @str << "end"
      false
    end

    def visit(node : ProcPointer)
      diagnostic_anchor(node, "ProcPointer", "arrow") { @str << "->" }
      @str << "::" if node.global?
      if obj = node.obj
        obj.accept self
        @str << '.'
      end
      diagnostic_name(node, node.name, "method_name")

      if node.args.size > 0
        @str << '('
        node.args.join(@str, ", ", &.accept self)
        @str << ')'
      end
      false
    end

    def visit(node : Def)
      @str << "abstract " if node.abstract?
      diagnostic_anchor(node, "Def", "keyword") { @str << "def" }
      @str << ' '
      if node_receiver = node.receiver
        node_receiver.accept self
        @str << '.'
      end
      diagnostic_name(node, node.name, "definition_name")
      if node.args.size > 0 || node.block_arity || node.double_splat
        @str << '('
        printed_arg = false
        node.args.each_with_index do |arg, i|
          @str << ", " if printed_arg
          @current_arg_type = :splat if node.splat_index == i
          drop_parens_for_proc_notation(arg, &.accept(self))
          printed_arg = true
        end
        if double_splat = node.double_splat
          @current_arg_type = :double_splat
          @str << ", " if printed_arg
          drop_parens_for_proc_notation(double_splat, &.accept(self))
          printed_arg = true
        end
        if block_arg = node.block_arg
          @current_arg_type = :block_arg
          @str << ", " if printed_arg
          drop_parens_for_proc_notation(block_arg, &.accept(self))
        elsif node.block_arity
          @str << ", " if printed_arg
          @str << '&'
        end
        @str << ')'
      end
      if return_type = node.return_type
        @str << " : "
        return_type.accept self
      end

      if free_vars = node.free_vars
        @str << " forall "
        free_vars.join(@str, ", ")
      end

      newline

      unless node.abstract?
        accept_with_indent(node.body)
        append_indent
        @str << "end"
      end
      false
    end

    def visit(node : Macro)
      # iyi: a macro travels in an artifact as this text, so what marks it
      # exported has to be in the text (R-2b, SPEC.md IV.4).
      @str << "pub " if node.exported?
      diagnostic_anchor(node, "Macro", "keyword") { @str << "macro" }
      @str << ' '
      diagnostic_name(node, node.name.to_s, "macro_name")
      if node.args.size > 0 || node.block_arg || node.double_splat
        @str << '('
        printed_arg = false
        # NOTE: `drop_parens_for_proc_notation` needed here if macros support
        # restrictions
        node.args.each_with_index do |arg, i|
          @str << ", " if printed_arg
          @current_arg_type = :splat if i == node.splat_index
          arg.accept self
          printed_arg = true
        end
        if double_splat = node.double_splat
          @str << ", " if printed_arg
          @current_arg_type = :double_splat
          double_splat.accept self
          printed_arg = true
        end
        if block_arg = node.block_arg
          @str << ", " if printed_arg
          @current_arg_type = :block_arg
          block_arg.accept self
        end
        @str << ')'
      end
      newline

      with_indent do
        inside_macro do
          accept node.body
        end
      end

      # newline
      append_indent
      @str << "end"
      false
    end

    def visit(node : MacroExpression)
      # A node starts multiline when its starting location (`{{` or `{%`) is on a different line than the start of its expression
      start_multiline = (start_loc = node.location) && (end_loc = node.exp.location) && end_loc.line_number > start_loc.line_number

      # and similarly ends multiline if its expression end location is on a different line than its end location (`}}` or `%}`)
      end_multiline = (body_end_loc = node.exp.end_location) && (end_loc = node.end_location) && end_loc.line_number > body_end_loc.line_number

      diagnostic_anchor(node, "MacroDirective", node.output? ? "expression" : "control") do
        @str << (node.output? ? "{{" : "{%")
      end
      @str << ' ' unless !node.output? && start_multiline

      if start_multiline
        newline
        @indent += 1
      end

      if (exp = node.exp).is_a? Expressions
        @root_level_macro_expressions = exp
      end

      outside_macro do
        write_extra_newlines node.location, node.exp.location

        # If the MacroExpression consists of a single node we need to manually handle appending indent and trailing newline if *start_multiline*
        # Otherwise, the Expressions logic handles that for us
        if start_multiline && !node.exp.is_a?(Expressions)
          append_indent
        end

        node.exp.accept self
      end

      write_extra_newlines node.exp.end_location, node.end_location

      # After writing the expression body, de-indent if things were originally multiline.
      # This ensures the ending control has the proper indent relative to the start.
      @indent -= 1 if start_multiline

      if end_multiline
        newline
        append_indent
      end

      @str << (node.output? ? " }}" : end_multiline ? "%}" : " %}")
      false
    end

    def visit(node : MacroIf)
      else_node = nil

      while true
        diagnostic_anchor(node, "MacroDirective", "control") { @str << "{%" }
        if node.is_unless?
          @str << " unless "
          then_node = node.else
          else_node = node.then
        else
          @str << (else_node ? " elsif " : " if ")
          then_node = node.then
          else_node = node.else
        end
        node.cond.accept self
        @str << " %}"

        inside_macro do
          then_node.accept self
        end

        # combine `{% else %}{% if %}` into `{% elsif %}` (does not apply to
        # `{% unless %}`, nor when there is whitespace inbetween, as that would
        # show up as a `MacroLiteral`)
        if !node.is_unless? && else_node.is_a?(MacroIf) && !else_node.is_unless?
          node = else_node
        else
          break
        end
      end

      unless else_node.nop?
        @str << "{% else %}"
        inside_macro do
          else_node.accept self
        end
      end

      @str << "{% end %}"
      false
    end

    def visit(node : MacroFor)
      diagnostic_anchor(node, "MacroDirective", "control") { @str << "{%" }
      @str << " for "
      node.vars.join(@str, ", ", &.accept self)
      @str << " in "
      node.exp.accept self
      @str << " %}"
      inside_macro do
        node.body.accept self
      end
      @str << "{% end %}"
      false
    end

    def visit(node : MacroVar)
      @str << '%'
      @str << node.name
      if exps = node.exps
        @str << '{'
        exps.join(@str, ", ", &.accept self)
        @str << '}'
      end
      false
    end

    def visit(node : MacroLiteral)
      # These two can only come from an escaped sequence like \{ or \{%
      if node.value == "{" || node.value.starts_with?("{%")
        @str << "\\"
      end
      @str << node.value
      false
    end

    def visit(node : MacroVerbatim)
      diagnostic_anchor(node, "MacroDirective", "control") { @str << "{%" }
      @str << " verbatim do %}"

      with_indent do
        inside_macro do
          node.exp.accept self
        end
      end

      @str << "{% end %}"
      false
    end

    def visit(node : ExternalVar)
      @str << '$'
      @str << node.name
      if real_name = node.real_name
        @str << " = "
        @str << real_name
      end
      @str << " : "
      node.type_spec.accept self
      false
    end

    def visit(node : Arg)
      enum_member = @inside_enum_member
      @inside_enum_member = false
      if parsed_annotations = node.parsed_annotations
        parsed_annotations.each do |ann|
          ann.accept self
          @str << ' '
        end
      end

      case @current_arg_type
      when .splat?        then @str << '*'
      when .double_splat? then @str << "**"
      when .block_arg?    then @str << '&'
      end

      if node.external_name != node.name
        diagnostic_external_name(node)
        @str << ' '
      end
      if name = node.name
        diagnostic_arg_name(node, name, enum_member)
      else
        @str << '?'
      end
      if restriction = node.restriction
        @str << " : "
        restriction.accept self
      end
      if default_value = node.default_value
        @str << " = "
        default_value.accept self
      end
      false
    ensure
      @inside_enum_member = enum_member || false
      @current_arg_type = :none
    end

    def visit(node : ProcNotation)
      @str << '(' unless drop_parens_for_proc_notation?

      # only drop the outermost pair of parentheses; this produces
      # `foo(x : (T -> U) -> V, W)`, not
      # `foo(x : ((T -> U) -> V), W)` nor `foo(x : T -> U -> V, W)`
      drop_parens_for_proc_notation(false) do
        if inputs = node.inputs
          inputs.join(@str, ", ", &.accept self)
          @str << ' '
        end
        @str << "->"
        if output = node.output
          @str << ' '
          output.accept self
        end
      end

      @str << ')' unless drop_parens_for_proc_notation?
      false
    end

    def visit(node : Self)
      @str << "self"
      false
    end

    def visit(node : Path)
      @str << "::" if node.global?
      node.names.each_with_index do |name, index|
        @str << "::" if index > 0
        diagnostic_name(node, name, "path_segment", DiagnosticNameSlot.new(DiagnosticNameSlotKind::PathSegment, index))
      end
      false
    end

    def visit(node : Generic)
      node.name.accept self

      printed_arg = false

      @str << '('
      node.type_vars.join(@str, ", ") do |var|
        var.accept self
        printed_arg = true
      end

      if named_args = node.named_args
        named_args.each do |named_arg|
          @str << ", " if printed_arg
          diagnostic_named_entry(named_arg, named_arg.name, DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry))
          @str << ": "
          named_arg.value.accept self
          printed_arg = true
        end
      end

      @str << ')'
      false
    end

    def visit_named_arg_name(name)
      Symbol.quote_for_named_argument(@str, name)
    end

    def visit(node : Underscore)
      @str << '_'
      false
    end

    def visit(node : Splat)
      @str << '*'
      accept_as_expression node.exp
      false
    end

    def visit(node : DoubleSplat)
      @str << "**"
      accept_as_expression node.exp
      false
    end

    def visit(node : Union)
      @str << "(" if node.parens?

      if node.singleton?
        drop_parens_for_proc_notation(node.types.first, &.accept(self))
      else
        node.types.join(@str, " | ", &.accept self)
      end

      @str << ")" if node.parens?
      false
    end

    # iyi: `Int32?.class` is a `Union` without parens; written bare it reads
    # back as `Int32 | Nil.class`.
    def visit(node : Metaclass)
      name = node.name
      needs_parens = name.is_a?(Union) && !name.parens?
      @str << "(" if needs_parens
      name.accept self
      @str << ")" if needs_parens
      @str << ".class"
      false
    end

    def visit(node : InstanceVar)
      diagnostic_name(node, node.name, "instance_variable")
      false
    end

    def visit(node : ReadInstanceVar)
      node.obj.accept self
      @str << '.'
      diagnostic_name(node, node.name, "instance_variable")
      false
    end

    def visit(node : ClassVar)
      diagnostic_name(node, node.name, "class_variable")
      false
    end

    def visit(node : Yield)
      if scope = node.scope
        @str << "with "
        scope.accept self
        @str << ' '
      end
      @str << "yield"
      in_parenthesis(node.has_parentheses?) do
        if node.exps.size > 0
          @str << ' ' unless node.has_parentheses?
          node.exps.join(@str, ", ") { |exp| accept_as_expression exp }
        end
      end
      false
    end

    def visit(node : Return)
      visit_control node, "return"
    end

    def visit(node : Break)
      visit_control node, "break"
    end

    def visit(node : Next)
      visit_control node, "next"
    end

    def visit_control(node, keyword)
      @str << keyword
      if exp = node.exp
        @str << ' '
        accept_as_expression exp
      end
      false
    end

    def visit(node : RegexLiteral)
      if (exp = node.value).is_a?(StringLiteral) && exp.value.empty?
        # // is not always an empty regex, sometimes is an operator
        # so it's safer to emit empty regex as %r()
        diagnostic_anchor(node, "Literal", "regex") { @str << "%r(" }
        @str << ')'
      else
        diagnostic_anchor(node, "Literal", "regex") { @str << '/' }
        case exp = node.value
        when StringLiteral
          @str << '\\' if exp.value[0]?.try &.ascii_whitespace?
          append_regex_source exp.value, @str
        when StringInterpolation
          diagnostic_anchor(exp, "Literal", "interpolation")
          @str << '\\' if exp.expressions.first?.as?(StringLiteral).try &.value[0]?.try &.ascii_whitespace?
          visit_interpolation(exp) { |s| append_regex_source s, @str }
        else
          raise "Bug: shouldn't happen"
        end
        @str << '/'
      end
      @str << 'i' if node.options.ignore_case?
      @str << 'm' if node.options.multiline?
      @str << 'x' if node.options.extended?
      false
    end

    # iyi: was `Regex.append_source`, the AST printer's last reference to the
    # stdlib Regex. Escaping a pattern back into a literal is two rules, so
    # they live here rather than keeping this file tied to `regex.cr` (SPEC.md
    # III.10): a backslash stays with the character it escapes, and the
    # delimiter is escaped.
    private def append_regex_source(source : String, io)
      reader = Char::Reader.new(source)
      while reader.has_next?
        case char = reader.current_char
        when '\\'
          io << '\\'
          io << reader.next_char
        when '/'
          io << "\\/"
        else
          io << char
        end
        reader.next_char
      end
    end

    def visit(node : TupleLiteral)
      first = node.elements.first?
      unless first
        start = @str.pos.to_i32 if @diagnostic_emissions || @diagnostic_generated_text
        @str << "::Tuple."
        method_start = @str.pos.to_i32 if @diagnostic_emissions
        @str << "new"
        if emissions = @diagnostic_emissions
          emissions << DiagnosticMacroAnchor.new(method_start.not_nil!, @str.pos.to_i32, "Call", "method", @diagnostic_emitter, nil, DiagnosticMacroProducer::EmptyTupleProjection)
        end
        if generated = @diagnostic_generated_text
          generated << DiagnosticGeneratedText.new(start.not_nil!, @str.pos.to_i32, @diagnostic_emitter, DiagnosticMacroProducer::EmptyTupleProjection)
        end
        return false
      end

      @str << '{'

      space = first.is_a?(TupleLiteral) || first.is_a?(NamedTupleLiteral) || first.is_a?(HashLiteral)
      @str << ' ' if space
      node.elements.join(@str, ", ") { |element| accept_as_expression element }
      @str << ' ' if space
      @str << '}'
      false
    end

    def visit(node : TypeDeclaration)
      diagnostic_anchor(node, "Assign", "constant") if node.var.is_a?(Path)
      node.var.accept self
      @str << " : "
      node.declared_type.accept self
      if value = node.value
        @str << " = "
        value.accept self
      end
      false
    end

    def visit(node : UninitializedVar)
      node.var.accept self
      @str << " = uninitialized "
      node.declared_type.accept self
      false
    end

    def visit(node : Block)
      # If the node's body end location is on the same line as the start of the block itself, it's on a single line.
      single_line_block = (node_loc = node.location) && (end_loc = node.body.end_location) && end_loc.line_number == node_loc.line_number

      diagnostic_anchor(node, "Block", "opener") { @str << "do" }

      if node.has_any_args?
        @str << " |"
        node.args.each_with_index do |arg, i|
          @str << ", " if i > 0
          @str << '*' if i == node.splat_index
          if arg.name == ""
            # This is an unpack
            unpack = node.unpacks.not_nil![i]
            visit_unpack(unpack)
          else
            arg.accept self
          end
        end
        @str << '|'
      end

      write_extra_newlines node.location, node.body.location

      if single_line_block
        @str << ' '
        node.body.accept self
      else
        newline
        accept_with_indent node.body
      end

      if single_line_block
        @str << ' '
      else
        append_indent
      end

      @str << "end"

      false
    end

    def visit_unpack(node)
      case node
      when Expressions
        @str << "("
        node.expressions.join(@str, ", ") do |exp|
          visit_unpack exp
        end
        @str << ")"
      else
        node.accept self
      end
    end

    def visit(node : Include)
      diagnostic_anchor(node, "Include", "keyword") { @str << "include" }
      @str << ' '
      node.name.accept self
      false
    end

    def visit(node : Extend)
      diagnostic_anchor(node, "Extend", "keyword") { @str << "extend" }
      @str << ' '
      node.name.accept self
      false
    end

    def visit(node : And)
      to_s_binary node, "&&"
    end

    def visit(node : Or)
      to_s_binary node, "||"
    end

    def visit(node : Not)
      @str << '.' if node.exp.is_a?(ImplicitObj)
      @str << '!'
      need_parens = need_parens(node.exp)
      in_parenthesis(need_parens, node.exp)
      false
    end

    def visit(node : VisibilityModifier)
      @str << node.modifier.to_s.downcase
      @str << ' '
      node.exp.accept self
      false
    end

    def to_s_binary(node, op)
      left_needs_parens = need_parens(node.left)
      left_parens_multiline = left_needs_parens && (begin_loc = node.left.location) && (end_loc = node.left.end_location) && (end_loc.line_number > begin_loc.line_number)
      in_parenthesis(left_needs_parens, node.left, left_parens_multiline)

      @str << ' '
      @str << op

      if (right_loc = node.right.location) && (left_end_loc = node.left.end_location) && (right_loc.line_number > left_end_loc.line_number)
        newline
        append_indent
      else
        @str << ' '
      end

      right_needs_parens = need_parens(node.right)
      right_parens_multiline = right_needs_parens && (begin_loc = node.right.location) && (end_loc = node.right.end_location) && (end_loc.line_number > begin_loc.line_number)
      in_parenthesis(right_needs_parens, node.right, right_parens_multiline)

      false
    end

    def visit(node : Global)
      if node.name == "$~" || node.name == "$?"
        diagnostic_name(node, node.name, "special_global")
      else
        @str << node.name
      end
      false
    end

    def visit(node : LibDef)
      @str << "lib "
      node.name.accept self
      newline
      accept_with_indent(node.body)
      append_indent
      @str << "end"
      false
    end

    def visit(node : FunDef)
      diagnostic_anchor(node, "FunDef", "keyword") { @str << "fun" }
      @str << ' '
      if node.name == node.real_name
        @str << node.name
      else
        @str << node.name
        @str << " = "
        Symbol.quote_for_named_argument(@str, node.real_name)
      end
      if node.args.size > 0
        @str << '('
        node.args.join(@str, ", ") do |arg|
          if arg_name = arg.name.presence
            @str << arg_name << " : "
          end
          drop_parens_for_proc_notation(arg) do
            arg.restriction.not_nil!.accept self
          end
        end
        if node.varargs?
          @str << ", ..."
        end
        @str << ')'
      elsif node.varargs?
        @str << "(...)"
      end
      if node_return_type = node.return_type
        @str << " : "
        node_return_type.accept self
      end
      if body = node.body
        newline
        accept_with_indent body
        append_indent
        @str << "end"
      end
      false
    end

    def visit(node : TypeDef)
      @str << "type "
      @str << node.name.to_s
      @str << " = "
      node.type_spec.accept self
      false
    end

    def visit(node : CStructOrUnionDef)
      @str << (node.union? ? "union" : "struct")
      @str << ' '
      @str << node.name.to_s
      newline
      accept_with_indent node.body
      append_indent
      @str << "end"
      false
    end

    def visit(node : EnumDef)
      @str << "pub " if node.exported?
      @str << "enum "
      node.name.accept self
      if base_type = node.base_type
        @str << " : "
        base_type.accept self
      end
      newline
      with_indent do
        node.members.each do |member|
          append_indent
          previous = @inside_enum_member
          @inside_enum_member = true
          begin
            member.accept self
          ensure
            @inside_enum_member = previous
          end
          newline
        end
      end
      append_indent
      @str << "end"
      false
    end

    def visit(node : RangeLiteral)
      unless node.from.nop?
        need_parens = need_parens(node.from)
        in_parenthesis(need_parens, node.from)
      end
      diagnostic_anchor(node, "Literal", "range") { @str << (node.exclusive? ? "..." : "..") }

      unless node.to.nop?
        need_parens = need_parens(node.to)
        in_parenthesis(need_parens, node.to)
      end

      false
    end

    def visit(node : PointerOf)
      @str << "pointerof("
      node.exp.accept(self)
      @str << ')'
      false
    end

    def visit(node : SizeOf)
      @str << "sizeof("
      node.exp.accept(self)
      @str << ')'
      false
    end

    def visit(node : InstanceSizeOf)
      @str << "instance_sizeof("
      node.exp.accept(self)
      @str << ')'
      false
    end

    def visit(node : AlignOf)
      @str << "alignof("
      node.exp.accept(self)
      @str << ')'
      false
    end

    def visit(node : InstanceAlignOf)
      @str << "instance_alignof("
      node.exp.accept(self)
      @str << ')'
      false
    end

    def visit(node : OffsetOf)
      @str << "offsetof("
      node.offsetof_type.accept(self)
      @str << ", "
      node.offset.accept(self)
      @str << ')'
      false
    end

    def visit(node : IsA)
      node.obj.accept self
      if node.nil_check?
        @str << ".nil?"
      else
        @str << ".is_a?("
        node.const.accept self
        @str << ')'
      end
      false
    end

    def visit(node : Cast)
      visit_cast node, "as"
    end

    def visit(node : NilableCast)
      visit_cast node, "as?"
    end

    def visit_cast(node, keyword)
      need_parens = need_parens(node.obj)
      in_parenthesis(need_parens, node.obj)
      @str << '.'
      diagnostic_anchor(node, "Cast", "keyword") { @str << keyword }
      @str << '('
      node.to.accept self
      @str << ')'
      false
    end

    def visit(node : RespondsTo)
      node.obj.accept self
      @str << ".responds_to?("
      visit_symbol_literal_value node.name
      @str << ')'
      false
    end

    def visit(node : Require)
      @str << "require \""
      @str << node.string
      @str << '"'
      false
    end

    def visit(node : Case)
      diagnostic_anchor(node, "Literal", "case") { @str << "case" }
      if cond = node.cond
        @str << ' '
        accept_as_expression cond
      end
      newline

      node.whens.each do |wh|
        wh.accept self
      end

      if node_else = node.else
        append_indent
        @str << "else"
        newline
        accept_with_indent node_else
      end
      append_indent
      @str << "end"
      false
    end

    def visit(node : When)
      append_indent
      @str << (node.exhaustive? ? "in" : "when")
      @str << ' '
      node.conds.join(@str, ", ") { |cond| accept_as_expression cond }
      newline
      accept_with_indent node.body
      false
    end

    def visit(node : Select)
      diagnostic_anchor(node, "Literal", "select") { @str << "select" }
      newline
      node.whens.each do |a_when|
        append_indent
        @str << "when "
        a_when.conds.first.accept self
        newline
        accept_with_indent a_when.body
      end
      if a_else = node.else
        append_indent
        @str << "else"
        newline
        accept_with_indent a_else
      end
      append_indent
      @str << "end"
      false
    end

    def visit(node : ImplicitObj)
      false
    end

    def visit(node : ExceptionHandler)
      @str << "begin"
      newline

      accept_with_indent node.body

      node.rescues.try &.each do |a_rescue|
        append_indent
        a_rescue.accept self
      end

      if node_else = node.else
        append_indent
        @str << "else"
        newline
        accept_with_indent node_else
      end

      if node_ensure = node.ensure
        append_indent
        @str << "ensure"
        newline
        accept_with_indent node_ensure
      end

      append_indent
      @str << "end"
      false
    end

    def visit(node : Rescue)
      @str << "rescue"
      if name = node.name
        @str << ' '
        @str << name
      end
      if (types = node.types) && types.size > 0
        if node.name
          @str << " :"
        end
        @str << ' '
        types.join(@str, " | ", &.accept self)
      end
      newline
      accept_with_indent node.body
      false
    end

    def visit(node : Alias)
      @str << "alias "
      node.name.accept self
      @str << " = "
      node.value.accept self
      false
    end

    def visit(node : TypeOf)
      @str << "typeof("
      node.expressions.join(@str, ", ", &.accept self)
      @str << ')'
      false
    end

    def visit(node : Annotation)
      @str << "@["
      @str << node.path
      if !node.args.empty? || node.named_args
        @str << '('
        printed_arg = false
        node.args.join(@str, ", ") do |arg|
          arg.accept self
          printed_arg = true
        end
        if named_args = node.named_args
          named_args.each do |named_arg|
            @str << ", " if printed_arg
            diagnostic_named_entry(named_arg, named_arg.name, DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry))
            @str << ": "
            named_arg.value.accept self
            printed_arg = true
          end
        end
        @str << ')'
      end
      @str << ']'
      false
    end

    def visit(node : MagicConstant)
      @str << node.name
      false
    end

    def visit(node : Asm)
      @str << "asm("
      node.text.inspect(@str)
      @str << " :"
      if outputs = node.outputs
        @str << ' '
        outputs.join(@str, ", ", &.accept self)
        @str << ' '
      end
      @str << ':'
      if inputs = node.inputs
        @str << ' '
        inputs.join(@str, ", ", &.accept self)
        @str << ' '
      end
      @str << ":"
      if clobbers = node.clobbers
        @str << ' '
        clobbers.join(@str, ", ", &.inspect @str)
        @str << ' '
      end
      @str << ":"
      if node.volatile? || node.alignstack? || node.intel? || node.can_throw?
        @str << ' '
        comma = false
        if node.volatile?
          @str << %("volatile")
          comma = true
        end
        if node.alignstack?
          @str << ", " if comma
          @str << %("alignstack")
          comma = true
        end
        if node.intel?
          @str << ", " if comma
          @str << %("intel")
          comma = true
        end
        if node.can_throw?
          @str << ", " if comma
          @str << %("unwind")
        end
      end
      @str << ')'
      false
    end

    def visit(node : AsmOperand)
      node.constraint.inspect(@str)
      @str << '('
      node.exp.accept self
      @str << ')'
      false
    end

    def newline
      @str << '\n'
    end

    def indent_string
      "  "
    end

    def append_indent
      @indent.times do
        @str << indent_string
      end
    end

    def with_indent(&)
      @indent += 1
      yield
      @indent -= 1
    end

    def accept_with_indent(node : Expressions)
      with_indent do
        append_indent unless node.keyword.none?
        node.accept self
      end
      newline unless node.keyword.none?
    end

    def accept_with_indent(node : Nop)
    end

    def accept_with_indent(node : ASTNode)
      with_indent do
        append_indent
        node.accept self
      end
      newline
    end

    def inside_macro(&)
      @inside_macro += 1
      yield
      @inside_macro -= 1
    end

    def outside_macro(&)
      old_inside_macro = @inside_macro
      @inside_macro = 0
      yield
      @inside_macro = old_inside_macro
    end

    def drop_parens_for_proc_notation(drop : Bool = true, &)
      old_drop_parens_for_proc_notation = @drop_parens_for_proc_notation
      @drop_parens_for_proc_notation = drop
      begin
        yield
      ensure
        @drop_parens_for_proc_notation = old_drop_parens_for_proc_notation
      end
    end

    def drop_parens_for_proc_notation(node : ASTNode, &)
      outermost_type_is_proc_notation =
        case node
        when Arg
          # def / fun parameters
          node.restriction.is_a?(ProcNotation)
        when TypeDeclaration
          # call arguments
          node.declared_type.is_a?(ProcNotation)
        else
          node.is_a?(ProcNotation)
        end

      drop_parens_for_proc_notation(outermost_type_is_proc_notation) { yield node }
    end

    def to_s : String
      @str.to_s
    end

    def to_s(io : IO) : Nil
      @str.to_s(io)
    end
  end
end
