# iyi: inlay hints, off the typed graph. Two kinds, both facts the
# compiler already established and the source merely omits:
#
#   x = parse(input)        →  x: Parser::Result = parse(input)
#   move(3, 7)              →  move(x: 3, y: 7)
#
# A type hint lands after a bare assignment's target — an assignment
# that spells its type already says it. A parameter hint lands before a
# positional literal argument — a variable passed by name documents
# itself, a bare `3` does not. Instantiations dedupe by position: a
# generic def typed many ways is still one line of source.
require "../syntax/ast"
require "../compiler"
require "../tools/typed_def_processor"

module Iyi::Lsp
  class InlayVisitor < Visitor
    include TypedDefProcessor

    KIND_TYPE      = 1
    KIND_PARAMETER = 2

    # line/column are iyi's 1-based units, naming the insertion point.
    record Hint, line : Int32, column : Int32, label : String, kind : Int32

    getter hints = [] of Hint
    @seen = Set({Int32, Int32, String}).new

    # TypedDefProcessor wants a target to name the file module; the
    # hints themselves filter by @file and the line range.
    @target_location : Location

    def initialize(@file : String, @from_line : Int32, @to_line : Int32)
      @target_location = Location.new(@file, @from_line, 1)
    end

    def process(result : Compiler::Result) : Array(Hint)
      process_result result
      result.node.accept self
      hints.sort_by! { |hint| {hint.line, hint.column} }
      hints
    end

    def process_typed_def(typed_def : Def) : Nil
      typed_def.accept self
    end

    def visit(node : Assign)
      target = node.target
      if target.is_a?(Var) &&
         (location = target.location) &&
         wanted?(location) &&
         (type = target.type?)
        add location.line_number,
          location.column_number + target.name.size,
          ": #{PrettyTypeNameJsonConverter.pretty_type_name(type)}",
          KIND_TYPE
      end
      true
    end

    def visit(node : Call)
      defs = node.target_defs
      if defs && defs.size == 1 && !node.expansion?
        params = defs.first.args
        node.args.each_with_index do |arg, index|
          break if index >= params.size
          next unless literal?(arg)
          location = arg.location
          next unless location && wanted?(location)
          name = params[index].external_name
          next if name.empty? || name.starts_with?('_')
          add location.line_number, location.column_number, "#{name}:", KIND_PARAMETER
        end
      end
      true
    end

    def visit(node)
      true
    end

    private def literal?(node : ASTNode) : Bool
      node.is_a?(NumberLiteral) || node.is_a?(StringLiteral) ||
        node.is_a?(CharLiteral) || node.is_a?(BoolLiteral) ||
        node.is_a?(NilLiteral) || node.is_a?(SymbolLiteral)
    end

    private def wanted?(location : Location) : Bool
      location.filename == @file &&
        location.line_number >= @from_line &&
        location.line_number <= @to_line
    end

    private def add(line : Int32, column : Int32, label : String, kind : Int32) : Nil
      @hints << Hint.new(line, column, label, kind) if @seen.add?({line, column, label})
    end
  end
end
