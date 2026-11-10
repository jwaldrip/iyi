require "../syntax/to_s"

module Iyi
  class ToSVisitor
    def visit(node : Arg)
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
        visit_named_arg_name(node.external_name)
        @str << ' '
      end
      if node.name
        @str << node.name
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
      @current_arg_type = :none
    end

    def visit(node : Primitive)
      @str << "# primitive: "
      @str << node.name
      false
    end

    def visit(node : MetaVar)
      @str << node.name
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
