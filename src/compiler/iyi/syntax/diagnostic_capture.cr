require "json"
require "base64"
require "set"
require "crystal/digest/sha256"

module Iyi
  enum DiagnosticCaptureInputKind
    SourceFile
    EntryBuffer
    MacroExpansion
  end

  enum DiagnosticCaptureParseEntry
    Parse
    ParseMode
    ParseToDef
  end

  enum DiagnosticCaptureParseMode
    Normal
    Lib
    LibStructOrUnion
    Enum
  end

  # A candidate capture input, not a frozen registry or proof of acceptance.
  # Callers must supply the parser's state before parsing, not reconstructed
  # state observed after it has mutated.
  class AcceptedCaptureInput
    MAX_INPUT_BYTES = 64 * 1024 * 1024

    getter kind : DiagnosticCaptureInputKind
    getter logical_module : String?
    getter package : String?
    getter original_file : String?
    getter lexical_mode : String
    getter entry : DiagnosticCaptureParseEntry
    getter mode : DiagnosticCaptureParseMode
    getter module_extends_written : Bool
    getter source_only : Bool
    getter visibility : Visibility?
    getter def_nest : Int32
    getter fun_nest : Int32
    getter type_nest : Int32
    getter wants_doc : Bool
    getter input_sha256 : String
    @input : String
    @scopes : Array(Array(String))

    def initialize(input : String, @kind : DiagnosticCaptureInputKind,
                   @logical_module : String?, @package : String?, @original_file : String?,
                   @lexical_mode : String, @entry : DiagnosticCaptureParseEntry,
                   @mode : DiagnosticCaptureParseMode, @module_extends_written : Bool,
                   @source_only : Bool, @visibility : Visibility?, @def_nest : Int32,
                   @fun_nest : Int32, @type_nest : Int32, @wants_doc : Bool,
                   scopes : Array(Array(String)))
      raise ArgumentError.new("capture input exceeds 64 MiB") if input.bytesize > MAX_INPUT_BYTES
      raise ArgumentError.new("capture input is not UTF-8") unless input.valid_encoding?
      raise ArgumentError.new("unknown capture lexical mode") unless {"Iyi", "Crystal"}.includes?(@lexical_mode)
      raise ArgumentError.new("invalid capture nesting") if @def_nest < 0 || @fun_nest < 0 || @type_nest < 0
      raise ArgumentError.new("capture parser scopes missing") if scopes.empty?
      if @entry.parse_to_def?
        raise ArgumentError.new("parse_to_def capture requires its original Def context")
      end
      if @kind.macro_expansion?
        raise ArgumentError.new("macro capture requires expansion binding, parent lineage, and pragma inputs")
      end
      if @kind.source_file? && (@original_file.nil? || @original_file.not_nil!.empty?)
        raise ArgumentError.new("source capture requires original file identity")
      end
      @input = input.dup
      @input_sha256 = ::Crystal::Digest::SHA256.hexdigest(@input)
      @scopes = scopes.map(&.dup)
    end

    def input : String
      @input.dup
    end

    def scopes : Array(Array(String))
      @scopes.map(&.dup)
    end

    # This compares only the candidate's recorded fields, not the complete
    # parser contract, which must be checked separately before acceptance.
    def same_candidate?(other : AcceptedCaptureInput, source : String) : Bool
      @input == source && @input == other.stored_input &&
        @kind == other.kind && @logical_module == other.logical_module &&
        @package == other.package && @original_file == other.original_file &&
        @lexical_mode == other.lexical_mode && @entry == other.entry &&
        @mode == other.mode && @module_extends_written == other.module_extends_written &&
        @source_only == other.source_only && @visibility == other.visibility &&
        @def_nest == other.def_nest && @fun_nest == other.fun_nest &&
        @type_nest == other.type_nest && @wants_doc == other.wants_doc &&
        @scopes == other.stored_scopes
    end

    def matches_source_token?(token : DiagnosticSourceNameToken) : Bool
      return false unless token.input_sha256 == @input_sha256 &&
                          token.input_bytesize == @input.bytesize &&
                          token.lexical_mode == @lexical_mode &&
                          token.input_start >= 0 && token.input_end <= @input.bytesize
      @input.to_slice[token.input_start, token.input_end - token.input_start] == token.raw_text.to_slice
    end

    protected def stored_input : String
      @input
    end

    protected def stored_scopes : Array(Array(String))
      @scopes
    end
  end

  private class DiagnosticCaptureOutput < IO
    @buffer = IO::Memory.new
    @written : Int64 = 0_i64

    def initialize(@limit : Int64)
    end

    def read(slice : Bytes) : Int32
      raise IO::Error.new("capture output is write-only")
    end

    def write(slice : Bytes) : Nil
      raise ArgumentError.new("capture snapshot exceeds size limit") if slice.size.to_i64 > @limit - @written
      @buffer.write(slice)
      @written += slice.size
    end

    def snapshot : String
      @buffer.to_s
    end
  end

  # Frozen ordered pragma input, not an authenticated parse or registry.
  class DiagnosticPragmaSnapshot
    MAX_BYTES = 64_i64 * 1024 * 1024
    getter sha256 : String
    @bytes : String
    @graph_budget : UInt64 = DiagnosticOrigin::MAX_UNFOLDED_BYTES

    def initialize(pragmas : Hash(Int32, Array(Lexer::LocPragma))?)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      json.object do
        json.field "present", !pragmas.nil?
        json.field "entries" do
          json.array do
            if entries = pragmas
              entries.each do |offset, list|
                raise ArgumentError.new("negative pragma offset") if offset < 0
                json.object do
                  json.field "offset", offset
                  json.field("pragmas") { json.array { list.each { |pragma| write_pragma(json, pragma) } } }
                end
              end
            end
          end
        end
      end
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      @bytes.dup
    end

    private def charge_graph(bytes : UInt64) : Nil
      raise ArgumentError.new("pragma graph exceeds size limit") if bytes > @graph_budget
      @graph_budget -= bytes
    end

    private def charge_origin(origin : DiagnosticOrigin?) : Nil
      return unless origin
      raise ArgumentError.new("pragma origin exceeds depth limit") if origin.graph_depth > DiagnosticOrigin::MAX_DEPTH
      charge_graph(origin.graph_bytes)
    end

    private def write_writer(json : JSON::Builder, writer : DiagnosticWriterRef) : Nil
      raise ArgumentError.new("invalid pragma writer extent") if writer.start_offset < 0 || writer.end_offset < writer.start_offset
      json.object do
        json.field "start", writer.start_offset
        json.field "end", writer.end_offset
      end
    end

    private def write_key(json : JSON::Builder, key : DiagnosticMacroClaimKey) : Nil
      json.object do
        json.field("writer") { write_writer(json, key.writer) }
        json.field "kind", key.kind
        json.field "role", key.role
      end
    end

    private def write_attachment(json : JSON::Builder, attachment : DiagnosticMacroAttachment) : Nil
      json.object do
        case attachment
        when DiagnosticMacroAttachment::Direct
          json.field "kind", "Direct"
          json.field("writer") { write_writer(json, attachment.writer) }
        when DiagnosticMacroAttachment::HeadOf
          json.field "kind", "HeadOf"
          json.field "rule", attachment.rule.to_s
          json.field "head" do
            json.object do
              case head = attachment.head
              when DiagnosticMacroHead::Anchor
                json.field "kind", "Anchor"
                json.field("writer") { write_writer(json, head.writer) }
              when DiagnosticMacroHead::Syntax
                json.field "kind", "Syntax"
                json.field "form", head.form.to_s
                json.field("writer") { write_writer(json, head.writer) }
                json.field "adjacent_name_writer" do
                  if adjacent = head.adjacent_name_writer
                    write_writer(json, adjacent)
                  else
                    json.null
                  end
                end
              else
                raise ArgumentError.new("unclassified pragma macro head")
              end
            end
          end
        when DiagnosticMacroAttachment::PayloadOf
          json.field "kind", "PayloadOf"
          json.field "rule", attachment.rule.to_s
          json.field("owner_key") { write_key(json, attachment.owner_key) }
        else
          raise ArgumentError.new("unclassified pragma macro attachment")
        end
      end
    end

    private def write_claim(json : JSON::Builder, claim : DiagnosticMacroClaim) : Nil
      charge_origin(claim.emitter_origin)
      case evidence = claim.evidence
      when DiagnosticAnchorEvidence::Spliced
        charge_origin(evidence.source_origin)
      when DiagnosticAnchorEvidence::Constructed, DiagnosticAnchorEvidence::DerivedFromOwner
      when DiagnosticAnchorEvidence::RawSyntax
        evidence.witnesses.each do |witness|
          raise ArgumentError.new("pragma witness exceeds depth limit") if witness.event.graph_depth > DiagnosticOrigin::MAX_DEPTH
          charge_graph(witness.event.graph_bytes)
        end
      else
        raise ArgumentError.new("unclassified pragma anchor evidence")
      end
      json.object do
        json.field("key") { write_key(json, claim.key) }
        json.field "evidence", claim.evidence
        json.field("attachment") { write_attachment(json, claim.attachment) }
        json.field "emitter_origin", claim.emitter_origin
      end
    end

    private def write_pragma(json : JSON::Builder, pragma : Lexer::LocPragma) : Nil
      json.object do
        case pragma
        when Lexer::LocSetPragma
          json.field "kind", "Set"
          json.field "filename", pragma.filename
          json.field "line", pragma.line_number
          json.field "column", pragma.column_number
          json.field "artifact", pragma.artifact
        when Lexer::LocPushPragma
          json.field "kind", "Push"
        when Lexer::LocPopPragma
          json.field "kind", "Pop"
        when Lexer::LocOriginPragma
          json.field "kind", "Origin"
          json.field "line", pragma.line_number
        when Lexer::LocDiagnosticEmission
          json.field "kind", "DiagnosticEmission"
          json.field "end", pragma.end_offset
          json.field("claims") { json.array { pragma.claims.each { |claim| write_claim(json, claim) } } }
          json.field "generated_text" do
            json.array do
              pragma.generated_text.each do |generated|
                charge_origin(generated.emitter_origin)
                json.object do
                  json.field "start", generated.start_offset
                  json.field "end", generated.end_offset
                  json.field "emitter_origin", generated.emitter_origin
                  json.field "producer", generated.producer.to_s
                end
              end
            end
          end
          json.field "name_fragments" do
            json.array do
              pragma.name_fragments.each do |fragment|
                charge_origin(fragment.emitter_origin)
                charge_graph(fragment.source_name.graph_bytes)
                json.object do
                  json.field "start", fragment.start_offset
                  json.field "end", fragment.end_offset
                  json.field "emitter_origin", fragment.emitter_origin
                  json.field "source_name", fragment.source_name
                end
              end
            end
          end
        else
          raise ArgumentError.new("unclassified pragma variant")
        end
      end
    end
  end

  # A structural filename snapshot, not a resolved authority graph. Macro
  # owners must already have a capture coordinate; this does not assert that
  # the coordinate resolves in a separately trusted registry.
  class DiagnosticFilenameSnapshot
    MAX_BYTES = 64_i64 * 1024 * 1024
    MAX_DEPTH = 128
    getter sha256 : String
    @bytes : String
    @seen = Set(UInt64).new

    def initialize(filename : String | VirtualFile | Nil)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      write_filename(json, filename, 0)
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      @bytes.dup
    end

    private def write_ref(json : JSON::Builder, ref : DiagnosticCaptureFieldRef) : Nil
      json.object do
        json.field "capture_id", ref.capture_id
        json.field "owner_path_json", ref.owner_path_json
        json.field "field_tag", ref.field_tag
        json.field "index", ref.index
        json.field "map_key", ref.map_key
      end
    end

    private def write_filename(json : JSON::Builder, filename : String | VirtualFile | Nil, depth : Int32) : Nil
      raise ArgumentError.new("filename graph exceeds depth limit") if depth > MAX_DEPTH
      json.object do
        case filename
        when Nil
          json.field "kind", "Absent"
        when String
          json.field "kind", "SourceFile"
          json.field "original_file", filename
        when VirtualFile
          id = filename.object_id
          raise ArgumentError.new("cyclic virtual filename") unless @seen.add?(id)
          begin
            owner = filename.macro.diagnostic_capture_ref || raise ArgumentError.new("virtual filename macro lacks capture reference")
            source = filename.source
            raise ArgumentError.new("virtual filename input exceeds size limit") if source.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
            json.field "kind", "VirtualFile"
            json.field "input_base64", Base64.strict_encode(source.to_slice)
            json.field "input_sha256", ::Crystal::Digest::SHA256.hexdigest(source)
            json.field("macro_owner") { write_ref(json, owner) }
            json.field "depth", filename.depth
            json.field "line_origins" do
              if origins = filename.line_origins
                json.array do
                  origins.each do |line, origin|
                    json.array { json.number(line); json.number(origin) }
                  end
                end
              else
                json.null
              end
            end
            json.field "expanded_location" do
              if location = filename.expanded_location
                json.object do
                  json.field "line", location.line_number
                  json.field "column", location.column_number
                  json.field "artifact", location.artifact
                  json.field("filename") { write_filename(json, location.filename, depth + 1) }
                end
              else
                json.null
              end
            end
          ensure
            @seen.delete(id)
          end
        else
          raise ArgumentError.new("unclassified filename binding")
        end
      end
    end
  end

  # Reads every Path.names element directly. This snapshot is an incremental
  # field encoder, not a complete AST census or a registry authority.
  class DiagnosticPathSnapshot
    getter sha256 : String
    @bytes : String

    def initialize(path : Path, input : AcceptedCaptureInput)
      names = path.names
      raise ArgumentError.new("path has no name segments") if names.empty?
      slots = path.diagnostic_name_slots
      if slots.size != names.size
        raise ArgumentError.new("path name evidence does not cover all segments")
      end
      origin = path.diagnostic_origin || raise ArgumentError.new("path lacks structural origin")
      raise ArgumentError.new("path origin exceeds depth limit") if origin.graph_depth > DiagnosticOrigin::MAX_DEPTH
      budget = DiagnosticOrigin::MAX_UNFOLDED_BYTES
      raise ArgumentError.new("path origin exceeds size limit") if origin.graph_bytes > budget
      budget -= origin.graph_bytes
      output = DiagnosticCaptureOutput.new(DiagnosticPragmaSnapshot::MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      json.object do
        json.field "node_kind", "Path"
        json.field "names" do
          json.array do
            names.each_with_index do |name, index|
              values = slots[DiagnosticNameSlot.new(DiagnosticNameSlotKind::PathSegment, index)]? ||
                       raise ArgumentError.new("missing path segment evidence at #{index}")
              raise ArgumentError.new("ambiguous path segment evidence at #{index}") unless values.size == 1
              value = values.first
              raise ArgumentError.new("path segment evidence differs at #{index}") unless value.rendered_text == name
              raise ArgumentError.new("path name evidence exceeds size limit") if value.graph_bytes > budget
              budget -= value.graph_bytes
              if value.is_a?(DiagnosticNameValue::Observed)
                token = value.source_token
                unless input.matches_source_token?(token)
                  raise ArgumentError.new("path segment evidence input mismatch at #{index}")
                end
              elsif !value.is_a?(DiagnosticNameValue::Derived)
                raise ArgumentError.new("unclassified path name evidence")
              end
              json.object do
                json.field "index", index
                json.field "value", name
                json.field "evidence", value
              end
            end
          end
        end
        json.field "global", path.global?
        json.field "visibility", path.visibility.to_s
        json.field "exported", path.exported?
        json.field "iyi_from_artifact", path.iyi_from_artifact?
        json.field "iyi_synthetic", path.iyi_synthetic?
        json.field("location") { write_location(json, path.location) }
        json.field("end_location") { write_location(json, path.end_location) }
        json.field "origin", origin
        json.field "macro_lineage", path.diagnostic_macro_lineage.to_s
      end
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      @bytes.dup
    end

    private def write_location(json : JSON::Builder, location : Location?) : Nil
      unless location
        json.null
        return
      end
      filename = DiagnosticFilenameSnapshot.new(location.filename)
      json.object do
        json.field "filename_snapshot", filename.bytes
        json.field "line", location.line_number
        json.field "column", location.column_number
        json.field "artifact", location.artifact
      end
    end
  end

  enum DiagnosticAstFieldClass
    Child
    ChildList
    NamedValue
    NamedChildMap
    SyntaxScalar
    OriginEvidence
    Infrastructure
  end

  # Closed incremental classification. Unknown kinds and fields are errors;
  # the entries here do not claim that the complete syntax schema is present.
  module DiagnosticAstFieldSchema
    SUPPORTED = %w(Path Generic Union TypeOf Arg NamedArgument Def Nop NilLiteral ImplicitObj Self Underscore
      Expressions BoolLiteral NumberLiteral CharLiteral StringLiteral SymbolLiteral MacroLiteral
      StringInterpolation ArrayLiteral TupleLiteral RangeLiteral RegexLiteral Var InstanceVar ClassVar
      Global ReadInstanceVar If Unless Assign OpAssign MultiAssign And Or ProcNotation)

    def self.classify(kind : String, field : String) : DiagnosticAstFieldClass
      case field
      when "location", "end_location", "diagnostic_origin", "diagnostic_macro_lineage",
           "diagnostic_name_slots", "diagnostic_literal_names", "diagnostic_literal_productions"
        return DiagnosticAstFieldClass::OriginEvidence if SUPPORTED.includes?(kind)
      when "diagnostic_capture_ref", "diagnostic_percent_witnesses"
        return DiagnosticAstFieldClass::Infrastructure if SUPPORTED.includes?(kind)
      when "dependencies", "observers", "enclosing_call", "dirty", "type"
        return DiagnosticAstFieldClass::Infrastructure if SUPPORTED.includes?(kind)
      end
      case kind
      when "Path"
        return DiagnosticAstFieldClass::NamedValue if field == "names"
        return DiagnosticAstFieldClass::SyntaxScalar if {"global", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if {"iyi_from_artifact", "iyi_synthetic"}.includes?(field)
      when "Generic"
        return DiagnosticAstFieldClass::Child if field == "name"
        return DiagnosticAstFieldClass::ChildList if {"type_vars", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "suffix"
      when "Union"
        return DiagnosticAstFieldClass::ChildList if field == "types"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "parens"
      when "TypeOf"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
      when "Arg"
        return DiagnosticAstFieldClass::NamedValue if {"name", "external_name"}.includes?(field)
        return DiagnosticAstFieldClass::Child if {"default_value", "restriction"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "parsed_annotations"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
      when "NamedArgument"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "value"
      when "Def"
        return DiagnosticAstFieldClass::NamedValue if {"name", "free_vars"}.includes?(field)
        return DiagnosticAstFieldClass::NamedChildMap if {"free_var_bounds", "where_bounds"}.includes?(field)
        return DiagnosticAstFieldClass::Child if {"receiver", "double_splat", "body", "block_arg", "return_type"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
        return DiagnosticAstFieldClass::SyntaxScalar if {"block_arity", "splat_index", "doc", "visibility", "exported",
          "iyi_from_impl", "macro_def", "abstract", "calls_super", "calls_initialize", "calls_previous_def",
          "uses_block_arg", "assigns_special_var"}.includes?(field)
      when "Expressions"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "keyword"
      when "BoolLiteral", "CharLiteral", "StringLiteral", "SymbolLiteral", "MacroLiteral"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "value"
      when "NumberLiteral"
        return DiagnosticAstFieldClass::SyntaxScalar if {"value", "kind"}.includes?(field)
      when "StringInterpolation"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "heredoc_indent"
      when "ArrayLiteral"
        return DiagnosticAstFieldClass::ChildList if field == "elements"
        return DiagnosticAstFieldClass::Child if {"of", "name"}.includes?(field)
      when "TupleLiteral"
        return DiagnosticAstFieldClass::ChildList if field == "elements"
      when "RangeLiteral"
        return DiagnosticAstFieldClass::Child if {"from", "to"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "exclusive"
      when "RegexLiteral"
        return DiagnosticAstFieldClass::Child if field == "value"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "options"
      when "Var", "InstanceVar", "ClassVar", "Global"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "Var" && field == "doc"
      when "ReadInstanceVar"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "If", "Unless"
        return DiagnosticAstFieldClass::Child if {"cond", "then", "else"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "else_location"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "If" && field == "ternary"
        return DiagnosticAstFieldClass::Infrastructure if kind == "If" && field == "iyi_definition_probe"
      when "Assign"
        return DiagnosticAstFieldClass::Child if {"target", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
      when "OpAssign"
        return DiagnosticAstFieldClass::Child if {"target", "value"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "op"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "MultiAssign"
        return DiagnosticAstFieldClass::ChildList if {"targets", "values"}.includes?(field)
      when "And", "Or"
        return DiagnosticAstFieldClass::Child if {"left", "right"}.includes?(field)
      when "ProcNotation"
        return DiagnosticAstFieldClass::ChildList if field == "inputs"
        return DiagnosticAstFieldClass::Child if field == "output"
      end
      raise ArgumentError.new("unclassified AST field #{kind}.#{field}")
    end
  end

  # One parser-observed literal constituent, represented as bytes rather than
  # as a UTF-8 string. Offsets are into the exact parser input.
  record DiagnosticLiteralSegment, start_offset : Int32, end_offset : Int32, raw_base64 : String

  # These observations describe what the parser actually consumed. They are
  # not authoritative until bound to an input and validated by the census.
  enum DiagnosticLiteralProduction
    Delimiter
    SymbolToken
    PercentSymbolElement
  end

  enum DiagnosticLiteralWitnessKind
    Opener
    StringPiece
    InterpolationStart
    InterpolationEnd
    ClosingDelimiter
    Continuation
  end

  record DiagnosticLiteralWitness, kind : DiagnosticLiteralWitnessKind, start_offset : Int32, end_offset : Int32 do
    def initialize(@kind : DiagnosticLiteralWitnessKind, @start_offset : Int32, @end_offset : Int32)
      raise ArgumentError.new("invalid literal witness span") unless @start_offset >= 0 && @end_offset > @start_offset
    end
  end

  class DiagnosticLiteralProductionSegment
    getter production : DiagnosticLiteralProduction
    getter start_offset : Int32
    getter end_offset : Int32
    getter raw_base64 : String
    getter delimiter_kind : String?
    getter nest : String?
    getter end_delimiter : String?
    getter allow_escapes : Bool?
    @witnesses : Array(DiagnosticLiteralWitness)

    def initialize(@production : DiagnosticLiteralProduction, @start_offset : Int32, @end_offset : Int32,
                   @raw_base64 : String, @delimiter_kind : String?, @nest : String?,
                   @end_delimiter : String?, @allow_escapes : Bool?,
                   witnesses : Array(DiagnosticLiteralWitness))
      raise ArgumentError.new("invalid literal production span") unless @start_offset >= 0 && @end_offset > @start_offset
      raise ArgumentError.new("literal production lacks witnesses") if witnesses.empty?
      if @production.delimiter? || @production.percent_symbol_element?
        if @delimiter_kind.nil? || @nest.nil? || @end_delimiter.nil? || @allow_escapes.nil?
          raise ArgumentError.new("delimiter production lacks delimiter state")
        end
      elsif !@delimiter_kind.nil? || !@nest.nil? || !@end_delimiter.nil? || !@allow_escapes.nil?
        raise ArgumentError.new("non-delimiter production has delimiter state")
      end
      witnesses.each do |witness|
        unless (witness.kind.continuation? && witness.end_offset <= @start_offset) ||
               (witness.start_offset >= @start_offset && witness.end_offset <= @end_offset)
          raise ArgumentError.new("literal witness outside production span")
        end
      end
      @witnesses = witnesses.dup
    end

    def witnesses : Array(DiagnosticLiteralWitness)
      @witnesses.dup
    end
  end

  class DiagnosticParsedLiteral
    getter input_sha256 : String
    getter input_bytesize : Int32
    getter lexical_mode : String
    getter decoded_base64 : String
    getter expansion : {DiagnosticOrigin, DiagnosticOrigin, String}?
    @segments : Array(DiagnosticLiteralSegment)

    def initialize(@input_sha256 : String, @input_bytesize : Int32, @lexical_mode : String,
                   @decoded_base64 : String, segments : Array(DiagnosticLiteralSegment),
                   @expansion : {DiagnosticOrigin, DiagnosticOrigin, String}?)
      raise ArgumentError.new("empty parsed literal") if segments.empty?
      previous_end = 0
      segments.each do |segment|
        unless segment.start_offset >= previous_end && segment.end_offset > segment.start_offset &&
               segment.end_offset <= @input_bytesize
          raise ArgumentError.new("invalid parsed literal constituent")
        end
        previous_end = segment.end_offset
      end
      @segments = segments.dup
    end

    def segments : Array(DiagnosticLiteralSegment)
      @segments.dup
    end
  end
end

module Iyi
  # A coordinate in one accepted parser input, not an assertion that the
  # coordinate resolves. Only the frozen capture registry can establish that.
  class DiagnosticCaptureFieldRef
    getter capture_id : String
    getter owner_path_json : String
    getter field_tag : String
    getter index : Int32?
    getter map_key : String?

    def initialize(@capture_id : String, @owner_path_json : String, @field_tag : String,
                   @index : Int32? = nil, @map_key : String? = nil)
      unless @capture_id.bytesize == 64 && @capture_id.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) }
        raise ArgumentError.new("invalid capture input identity")
      end
      raise ArgumentError.new("empty capture field tag") if @field_tag.empty?
      raise ArgumentError.new("invalid capture field index") if @index.try { |i| i < 0 }
      raise ArgumentError.new("ambiguous capture field coordinate") if @index && @map_key
      raise ArgumentError.new("invalid capture owner path") unless JSON.parse(@owner_path_json).as_a?
    end

    def_equals_and_hash @capture_id, @owner_path_json, @field_tag, @index, @map_key
  end
end
