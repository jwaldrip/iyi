require "../syntax/to_s"

module Iyi
  class ToSVisitor
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
      if type = node.type?
        @str << " : "
        TypeNode.new(type).accept(self)
      elsif restriction = node.restriction
        @str << " : "
        restriction.accept self
      end
      if default_value = node.default_value
        @str << " = "
        default_value.accept self
      end
      false
    ensure
      @inside_enum_member = enum_member
      @current_arg_type = :none
    end

    def visit(node : Primitive)
      @str << "# primitive: "
      @str << node.name
      false
    end

    def visit(node : MetaVar)
      if !@diagnostic_name_fragments && !@diagnostic_anchors && !@diagnostic_generated_text
        @str << node.name
      elsif node.diagnostic_name_slots.has_key?(DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary))
        diagnostic_name(node, node.name, node.name == "$~" || node.name == "$?" ? "special_global" : "local_reference")
      elsif node.diagnostic_origin && (@diagnostic_name_fragments || @diagnostic_anchors)
        raise ArgumentError.new("semantic variable lacks preserved name evidence")
      else
        diagnostic_raw(node, DiagnosticMacroProducer::SemanticPrinter) { @str << node.name }
      end
      false
    end

    def visit(node : MetaMacroVar)
      diagnostic_raw(node, DiagnosticMacroProducer::MacroVar) { @str << node.name }
      false
    end

    def visit(node : TypeFilteredNode)
      false
    end

    def visit(node : TypeNode)
      diagnostic_raw(node, DiagnosticMacroProducer::SemanticPrinter) { node.type.devirtualize.to_s(@str) }
      false
    end

    def visit(node : AssignWithRestriction)
      @str << "# type restriction: "
      node.assign.target.accept self
      @str << " : "
      node.restriction.accept self
      @str << " = "
      node.assign.value.accept self
      false
    end

    def visit(node : YieldBlockBinder)
      false
    end

    def visit(node : FileNode)
      @str.puts
      @str << "# " << node.filename
      @str.puts
      node.node.accept self
      false
    end

    def visit(node : External)
      node.fun_def?.try &.accept self
      false
    end

    def visit(node : MacroId)
      diagnostic_raw(node, DiagnosticMacroProducer::MacroId) { @str << node.value }
      false
    end

    def visit(node : Unreachable)
      @str << %(raise "unreachable")
      false
    end
  end
end
