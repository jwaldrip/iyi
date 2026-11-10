require "set"
require "./ast"
require "./diagnostic_msi"

module Iyi
  # Adapter from the stored state of an `ASTNode` graph to the `iyi-msi/1` node
  # model in `DiagnosticMsi`. It is fail-closed by construction:
  #
  # - Only the kinds in `schema` bind. Every other class is refused.
  # - Each bound kind reads exactly the stored fields listed for it. Base-class
  #   state that the wire cannot encode is refused whenever it is present:
  #   locations, origin, macro lineage, capture reference, explicit external
  #   name, literal names and productions, percent witnesses, name slots, and
  #   doc comments. A refusal is never a silent omission.
  # - The parser entry and input kind come from the envelope and are checked
  #   against an allowlist. ParseToDef and MacroExpansion are refused.
  # - The graph is copied into fresh wire nodes (`snapshot`) before the writer
  #   runs, so mutating the AST afterwards cannot change the bytes. Shared
  #   nodes map to one wire node, which the writer emits as an alias. Cycles
  #   and AST depth beyond `DiagnosticMsi::MAX_DEPTH` are refused.
  #
  # Status: a parsed source graph cannot bind. `Parser` attaches a `Location`
  # to nearly every node, and `iyi-msi/1` has no typed location or origin
  # record, so `bind` refuses it. Only location-free graphs built in code bind.
  # Nothing here establishes source binding, provenance, or authority. The
  # verifier checks bytes only.
  module DiagnosticMsiAst
    # Parser entries that may bind. ParseToDef needs its original Def context.
    ENTRIES = ["Parse", "ParseMode"]

    # Input kinds that may bind. MacroExpansion needs expansion binding and lineage.
    INPUT_KINDS = ["SourceFile", "EntryBuffer"]

    # Each bound kind, with its stored wire fields in schema order.
    def self.schema : Hash(String, Array(String))
      {
        "Nop"                 => [] of String,
        "NilLiteral"          => [] of String,
        "BoolLiteral"         => ["value"],
        "NumberLiteral"       => ["value", "kind"],
        "CharLiteral"         => ["value"],
        "StringLiteral"       => ["value"],
        "SymbolLiteral"       => ["value"],
        "StringInterpolation" => ["expressions", "heredoc_indent"],
        "Expressions"         => ["expressions", "keyword"],
      } of String => Array(String)
    end

    # Binds a graph into a verified bundle. Every refusal happens before the
    # writer emits a byte, and the result is verified before it is returned.
    def self.bind(root : ASTNode, input : Bytes, tag : String, envelope : JSON::Any, tool : String) : DiagnosticMsi::Bundle
      check_envelope(envelope)
      frozen = snapshot(root)
      bundle = DiagnosticMsi::Writer.new(schema).write(frozen, copy_bytes(input), tag, envelope, tool)
      DiagnosticMsi.verify(bundle.root, bundle.shards, schema)
      bundle
    end

    # Copies the stored state of `root` into fresh wire nodes. Once this
    # returns, nothing in the result refers back into the AST.
    def self.snapshot(root : ASTNode) : DiagnosticMsi::Node
      Snapshotter.new.visit(root, 0)
    end

    def self.check_envelope(envelope : JSON::Any) : Nil
      object = envelope.as_h? || raise ArgumentError.new("MSI capture envelope is not an object")
      entry = object["entry"]?.try(&.as_s?) || raise ArgumentError.new("MSI capture envelope has no entry")
      input_kind = object["kind"]?.try(&.as_s?) || raise ArgumentError.new("MSI capture envelope has no input kind")
      raise ArgumentError.new("MSI refuses parser entry #{entry}") unless ENTRIES.includes?(entry)
      raise ArgumentError.new("MSI refuses input kind #{input_kind}") unless INPUT_KINDS.includes?(input_kind)
    end

    def self.copy_bytes(source : Bytes) : Bytes
      copy = Bytes.new(source.size)
      copy.copy_from(source)
      copy
    end

    # Refuses any base-class state the wire cannot encode. Reads stored values
    # only: `Expressions#location` is derived from children, so it is not used.
    def self.refuse_stored_state(ast : ASTNode) : Nil
      name = ast.class_desc
      if ast.diagnostic_stored_location || ast.diagnostic_stored_end_location
        raise ArgumentError.new("MSI refuses located #{name}: iyi-msi/1 has no location record")
      end
      raise ArgumentError.new("MSI refuses #{name} with a diagnostic origin") if ast.diagnostic_origin
      raise ArgumentError.new("MSI refuses #{name} with macro lineage") unless ast.diagnostic_macro_lineage.unknown?
      raise ArgumentError.new("MSI refuses #{name} with a capture reference") if ast.diagnostic_capture_ref
      raise ArgumentError.new("MSI refuses #{name} with an explicit external name") if ast.diagnostic_external_explicit
      raise ArgumentError.new("MSI refuses #{name} with literal names") if ast.diagnostic_literal_names_present?
      raise ArgumentError.new("MSI refuses #{name} with literal productions") if ast.diagnostic_literal_productions_present?
      raise ArgumentError.new("MSI refuses #{name} with percent witnesses") if ast.diagnostic_percent_witnesses?
      raise ArgumentError.new("MSI refuses #{name} with name slots") if ast.diagnostic_name_slots_present?
      raise ArgumentError.new("MSI refuses #{name} with a doc comment") if ast.doc
    end

    # Depth-first copy with explicit memo and active-path sets. Refusals are
    # raised during the walk, so no wire node escapes a failed snapshot.
    class Snapshotter
      def initialize
        @done = {} of UInt64 => DiagnosticMsi::Node
        @active = Set(UInt64).new
      end

      def visit(ast : ASTNode, depth : Int32) : DiagnosticMsi::Node
        raise ArgumentError.new("MSI AST depth exceeds #{DiagnosticMsi::MAX_DEPTH}") if depth > DiagnosticMsi::MAX_DEPTH
        id = ast.object_id
        if done = @done[id]?
          return done
        end
        raise ArgumentError.new("MSI cycle through #{ast.class_desc}") if @active.includes?(id)
        DiagnosticMsiAst.refuse_stored_state(ast)
        @active.add(id)
        node = DiagnosticMsi::Node.new(ast.class_desc, fields_for(ast, depth))
        @active.delete(id)
        @done[id] = node
        node
      end

      private def fields_for(ast : ASTNode, depth : Int32) : Array(DiagnosticMsi::Field)
        case ast
        when Nop, NilLiteral
          [] of DiagnosticMsi::Field
        when BoolLiteral
          [field("value", DiagnosticMsi::Value.flag(ast.value))]
        when NumberLiteral
          [
            field("value", octets(ast.value)),
            field("kind", DiagnosticMsi::Value.identifier(ast.kind.to_s)),
          ]
        when CharLiteral
          [field("value", DiagnosticMsi::Value.number(ast.value.ord.to_i64))]
        when StringLiteral, SymbolLiteral
          [field("value", octets(ast.value))]
        when StringInterpolation
          [
            field("expressions", DiagnosticMsi::Value.children(children(ast.expressions, depth))),
            field("heredoc_indent", DiagnosticMsi::Value.number(ast.heredoc_indent.to_i64)),
          ]
        when Expressions
          [
            field("expressions", DiagnosticMsi::Value.children(children(ast.expressions, depth))),
            field("keyword", DiagnosticMsi::Value.identifier(ast.keyword.to_s)),
          ]
        else
          raise ArgumentError.new("MSI does not bind #{ast.class_desc}: no schema entry")
        end
      end

      private def children(list : Array(ASTNode), depth : Int32) : Array(DiagnosticMsi::Node)
        list.map { |child| visit(child, depth + 1) }
      end

      private def field(name : String, value : DiagnosticMsi::Value) : DiagnosticMsi::Field
        DiagnosticMsi::Field.new(name, value)
      end

      private def octets(text : String) : DiagnosticMsi::Value
        DiagnosticMsi::Value.octets(DiagnosticMsiAst.copy_bytes(text.to_slice))
      end
    end
  end
end
