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

    def input_bytesize : Int32
      @input.bytesize
    end

    def matches_encoded_span?(start_offset : Int32, end_offset : Int32, encoded : String) : Bool
      return false unless start_offset >= 0 && end_offset > start_offset && end_offset <= @input.bytesize
      return false if encoded.bytesize.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
      span = @input.to_slice[start_offset, end_offset - start_offset]
      return false if span.size.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64 * 3 // 4 - 4
      Base64.strict_encode(span) == encoded
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
    MAX_BYTES = 8_i64 * 1024 * 1024
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
      DiagnosticAstFieldSchema.validate_reflected_fields(path)
      names = path.names
      raise ArgumentError.new("path has no name segments") if names.empty?
      raise ArgumentError.new("path name inventory exceeds size limit") if names.size.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64 // 64
      if path.diagnostic_name_slots_count != names.size ||
         path.diagnostic_name_slots_graph_bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES
        raise ArgumentError.new("path name evidence does not cover all segments or exceeds the graph limit")
      end
      slots = Array(Indexable(DiagnosticNameValue)?).new(names.size, nil)
      path.each_diagnostic_name_slot do |slot, values|
        unless slot.kind.path_segment? && slot.index < names.size && slots[slot.index].nil?
          raise ArgumentError.new("invalid path name evidence slot")
        end
        slots[slot.index] = values
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
              values = slots[index] ||
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
        json.field("location") { write_location(json, path.diagnostic_stored_location) }
        json.field("end_location") { write_location(json, path.diagnostic_stored_end_location) }
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
    IndexedChildMap
    Record
    RecordList
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
      Global ReadInstanceVar If Unless Assign OpAssign MultiAssign And Or ProcNotation HashLiteral NamedTupleLiteral
      Block Call Macro Not PointerOf SizeOf InstanceSizeOf AlignOf InstanceAlignOf Out MacroVerbatim Splat DoubleSplat
      OffsetOf VisibilityModifier IsA RespondsTo Require When Case Select While Until Rescue ExceptionHandler
      Return Break Next Yield ClassDef TraitDef Propagate Defer Recover AssocTypeDecl ImplDef ModuleHeader
      ImportDecl UsingDecl ModuleDef AnnotationDef TypeDeclaration UninitializedVar ProcLiteral ProcPointer
      Include Extend LibDef FunDef TypeDef CStructOrUnionDef EnumDef ExternalVar Alias Metaclass Cast NilableCast
      Annotation MacroExpression MacroIf MacroFor MacroVar MagicConstant Asm AsmOperand)

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
        return DiagnosticAstFieldClass::Infrastructure if {"iyi_from_artifact", "iyi_synthetic", "target_const", "target_type", "syntax_replacement"}.includes?(field)
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
      when "BoolLiteral", "CharLiteral", "StringLiteral", "MacroLiteral"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "value"
      when "SymbolLiteral"
        return DiagnosticAstFieldClass::NamedValue if field == "value"
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
      when "HashLiteral"
        return DiagnosticAstFieldClass::RecordList if field == "entries"
        return DiagnosticAstFieldClass::Record if field == "of"
        return DiagnosticAstFieldClass::Child if field == "name"
      when "NamedTupleLiteral"
        return DiagnosticAstFieldClass::RecordList if field == "entries"
      when "HashLiteral::Entry"
        return DiagnosticAstFieldClass::Child if {"key", "value"}.includes?(field)
      when "NamedTupleLiteral::Entry"
        return DiagnosticAstFieldClass::NamedValue if field == "key"
        return DiagnosticAstFieldClass::Child if field == "value"
      when "Block"
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "splat_index"
        return DiagnosticAstFieldClass::IndexedChildMap if field == "unpacks"
        return DiagnosticAstFieldClass::Infrastructure if field == "call"
      when "Call"
        return DiagnosticAstFieldClass::Child if {"obj", "block", "block_arg"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if {"args", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "global", "expansion", "args_in_brackets",
          "has_parentheses", "iyi_group", "iyi_banged"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if {"name_location", "iyi_after_floor_div"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if {"name_size", "iyi_synthetic", "iyi_compiler_expansion", "iyi_open_dispatch"}.includes?(field)
      when "Macro"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if {"body", "double_splat", "block_arg"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::SyntaxScalar if {"splat_index", "doc", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "Not", "PointerOf", "SizeOf", "InstanceSizeOf", "AlignOf", "InstanceAlignOf", "Out",
           "MacroVerbatim", "Splat", "DoubleSplat", "Propagate", "Defer", "Return", "Break", "Next"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::Infrastructure if kind == "Return" && field == "from_propagate"
      when "OffsetOf"
        return DiagnosticAstFieldClass::Child if {"offsetof_type", "offset"}.includes?(field)
      when "VisibilityModifier"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::SyntaxScalar if {"modifier", "doc"}.includes?(field)
      when "IsA"
        return DiagnosticAstFieldClass::Child if {"obj", "const"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"nil_check", "error_construct", "iyi_bang_call"}.includes?(field)
      when "RespondsTo"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "Require"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "string"
        return DiagnosticAstFieldClass::Infrastructure if field == "iyi_prelude"
      when "When"
        return DiagnosticAstFieldClass::ChildList if field == "conds"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "exhaustive"
      when "Case"
        return DiagnosticAstFieldClass::Child if {"cond", "else"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "whens"
        return DiagnosticAstFieldClass::SyntaxScalar if {"exhaustive", "binds_it"}.includes?(field)
      when "Select"
        return DiagnosticAstFieldClass::ChildList if field == "whens"
        return DiagnosticAstFieldClass::Child if field == "else"
      when "While", "Until"
        return DiagnosticAstFieldClass::Child if {"cond", "body"}.includes?(field)
      when "Rescue"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::ChildList if field == "types"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "ExceptionHandler"
        return DiagnosticAstFieldClass::Child if {"body", "else", "ensure"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "rescues"
        return DiagnosticAstFieldClass::SyntaxScalar if {"implicit", "suffix"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if {"else_location", "ensure_location"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if field == "iyi_defer"
      when "Yield"
        return DiagnosticAstFieldClass::ChildList if field == "exps"
        return DiagnosticAstFieldClass::Child if field == "scope"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "has_parentheses"
      when "ClassDef"
        return DiagnosticAstFieldClass::Child if {"name", "body", "superclass"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "splat_index", "abstract", "struct", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "TraitDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "supertraits"
        return DiagnosticAstFieldClass::NamedValue if {"type_vars", "assoc_types"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "Recover"
        return DiagnosticAstFieldClass::Child if {"exp", "default"}.includes?(field)
      when "AssocTypeDecl"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "value"
        return DiagnosticAstFieldClass::SyntaxScalar if {"in_type_body", "doc"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "ImplDef"
        return DiagnosticAstFieldClass::Child if {"trait", "target", "body"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "trait_args"
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::NamedChildMap if {"type_var_bounds", "assoc_types"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "ModuleHeader"
        return DiagnosticAstFieldClass::NamedValue if field == "path"
      when "ImportDecl", "UsingDecl"
        return DiagnosticAstFieldClass::NamedValue if {"path", "names"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_locations"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "ImportDecl" && {"exported", "glob"}.includes?(field)
      when "ModuleDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::SyntaxScalar if {"splat_index", "doc", "visibility", "iyi_unit"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "AnnotationDef"
        return DiagnosticAstFieldClass::Child if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "TypeDeclaration"
        return DiagnosticAstFieldClass::Child if {"var", "declared_type", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
      when "UninitializedVar"
        return DiagnosticAstFieldClass::Child if {"var", "declared_type"}.includes?(field)
      when "ProcLiteral"
        return DiagnosticAstFieldClass::Child if field == "def"
      when "ProcPointer"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "global"
      when "Include", "Extend", "Metaclass"
        return DiagnosticAstFieldClass::Child if field == "name"
      when "LibDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "FunDef"
        return DiagnosticAstFieldClass::NamedValue if {"name", "real_name"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::Child if {"return_type", "body"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "varargs"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "TypeDef"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "type_spec"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "CStructOrUnionDef"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "union"}.includes?(field)
      when "EnumDef"
        return DiagnosticAstFieldClass::Child if {"name", "base_type"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "members"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
      when "ExternalVar"
        return DiagnosticAstFieldClass::NamedValue if {"name", "real_name"}.includes?(field)
        return DiagnosticAstFieldClass::Child if field == "type_spec"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
      when "Alias"
        return DiagnosticAstFieldClass::Child if {"name", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
      when "Cast", "NilableCast"
        return DiagnosticAstFieldClass::Child if {"obj", "to"}.includes?(field)
      when "Annotation"
        return DiagnosticAstFieldClass::Child if field == "path"
        return DiagnosticAstFieldClass::ChildList if {"args", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "iyi_file_mark"}.includes?(field)
      when "MacroExpression"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "output"
      when "MacroIf"
        return DiagnosticAstFieldClass::Child if {"cond", "then", "else"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "is_unless"
      when "MacroFor"
        return DiagnosticAstFieldClass::ChildList if field == "vars"
        return DiagnosticAstFieldClass::Child if {"exp", "body"}.includes?(field)
      when "MacroVar"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::ChildList if field == "exps"
      when "MagicConstant"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "name"
      when "Asm"
        return DiagnosticAstFieldClass::SyntaxScalar if {"text", "clobbers", "volatile", "alignstack", "intel", "can_throw"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if {"outputs", "inputs"}.includes?(field)
      when "AsmOperand"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "constraint"
        return DiagnosticAstFieldClass::Child if field == "exp"
      end
      raise ArgumentError.new("unclassified AST field #{kind}.#{field}")
    end

    # Call with a statically narrowed concrete node. The generic ASTNode type
    # cannot establish coverage of the subclass's stored fields.
    def self.validate_reflected_fields(node : T) : Nil forall T
      {% if T == ASTNode %}
        raise ArgumentError.new("AST field coverage requires a concrete node type")
      {% else %}
        kind = node.class.name.rpartition("::")[2]
        {% for ivar in T.instance_vars %}
          classify(kind, {{ivar.name.stringify}})
        {% end %}
      {% end %}
    end
  end

  # Direct syntax edges for the types below. The caller must separately encode
  # field presence, scalars, name evidence and origin metadata. This helper is
  # not a complete census and must not be used to authorize a capture.
  module DiagnosticDirectChildFields
    def self.each(node : ASTNode, & : String, Int32?, String?, ASTNode ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified direct AST node #{class_name}")
      end
      case node
      when Path
        # Path.names are scalar names, not child AST nodes.
      when Generic
        yield "name", nil, nil, node.name
        node.type_vars.each_with_index { |child, index| yield "type_vars", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
      when Union
        node.types.each_with_index { |child, index| yield "types", index, nil, child }
      when TypeOf
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when ProcNotation
        node.inputs.try &.each_with_index { |child, index| yield "inputs", index, nil, child }
        node.output.try { |child| yield "output", nil, nil, child }
      when NamedArgument
        yield "value", nil, nil, node.value
      when Arg
        node.default_value.try { |child| yield "default_value", nil, nil, child }
        node.restriction.try { |child| yield "restriction", nil, nil, child }
        node.parsed_annotations.try &.each_with_index { |child, index| yield "parsed_annotations", index, nil, child }
      when Def
        node.receiver.try { |child| yield "receiver", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.double_splat.try { |child| yield "double_splat", nil, nil, child }
        yield "body", nil, nil, node.body
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
        node.return_type.try { |child| yield "return_type", nil, nil, child }
        node.free_var_bounds.try &.each { |key, child| yield "free_var_bounds", nil, key, child }
        node.where_bounds.try &.each { |key, child| yield "where_bounds", nil, key, child }
      when Annotation
        yield "path", nil, nil, node.path
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
      when Nop, NilLiteral, ImplicitObj, Self, Underscore, BoolLiteral, NumberLiteral, CharLiteral,
           StringLiteral, SymbolLiteral, MacroLiteral, Var, InstanceVar, ClassVar, Global, MagicConstant
        # No syntax-child edges.
      when Expressions
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when StringInterpolation
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when ArrayLiteral
        node.elements.each_with_index { |child, index| yield "elements", index, nil, child }
        node.of.try { |child| yield "of", nil, nil, child }
        node.name.try { |child| yield "name", nil, nil, child }
      when TupleLiteral
        node.elements.each_with_index { |child, index| yield "elements", index, nil, child }
      when HashLiteral
        node.entries.each_with_index do |entry, index|
          yield "entries.key", index, nil, entry.key
          yield "entries.value", index, nil, entry.value
        end
        node.of.try do |entry|
          yield "of.key", nil, nil, entry.key
          yield "of.value", nil, nil, entry.value
        end
        node.name.try { |child| yield "name", nil, nil, child }
      when NamedTupleLiteral
        node.entries.each_with_index { |entry, index| yield "entries.value", index, nil, entry.value }
      when RangeLiteral
        yield "from", nil, nil, node.from
        yield "to", nil, nil, node.to
      when RegexLiteral
        yield "value", nil, nil, node.value
      when ReadInstanceVar
        yield "obj", nil, nil, node.obj
      when Block
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        yield "body", nil, nil, node.body
        node.unpacks.try &.each { |index, child| yield "unpacks", index, nil, child }
      when Call
        node.obj.try { |child| yield "obj", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
        node.block.try { |child| yield "block", nil, nil, child }
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
      when If, Unless
        yield "cond", nil, nil, node.cond
        yield "then", nil, nil, node.then
        yield "else", nil, nil, node.else
      when Assign, OpAssign
        yield "target", nil, nil, node.target
        yield "value", nil, nil, node.value
      when MultiAssign
        node.targets.each_with_index { |child, index| yield "targets", index, nil, child }
        node.values.each_with_index { |child, index| yield "values", index, nil, child }
      when And, Or
        yield "left", nil, nil, node.left
        yield "right", nil, nil, node.right
      when Macro
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        yield "body", nil, nil, node.body
        node.double_splat.try { |child| yield "double_splat", nil, nil, child }
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
      when Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out, MacroVerbatim, Splat, DoubleSplat,
           Propagate, Defer
        yield "exp", nil, nil, node.exp
      when Return, Break, Next
        node.exp.try { |child| yield "exp", nil, nil, child }
      when OffsetOf
        yield "offsetof_type", nil, nil, node.offsetof_type
        yield "offset", nil, nil, node.offset
      when VisibilityModifier
        yield "exp", nil, nil, node.exp
      when IsA
        yield "obj", nil, nil, node.obj
        yield "const", nil, nil, node.const
      when RespondsTo
        yield "obj", nil, nil, node.obj
      when Require
        # Its string is a scalar, not a child AST node.
      when When
        node.conds.each_with_index { |child, index| yield "conds", index, nil, child }
        yield "body", nil, nil, node.body
      when Case
        node.cond.try { |child| yield "cond", nil, nil, child }
        node.whens.each_with_index { |child, index| yield "whens", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
      when Select
        node.whens.each_with_index { |child, index| yield "whens", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
      when While, Until
        yield "cond", nil, nil, node.cond
        yield "body", nil, nil, node.body
      when Rescue
        yield "body", nil, nil, node.body
        node.types.try &.each_with_index { |child, index| yield "types", index, nil, child }
      when ExceptionHandler
        yield "body", nil, nil, node.body
        node.rescues.try &.each_with_index { |child, index| yield "rescues", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
        node.ensure.try { |child| yield "ensure", nil, nil, child }
      when Yield
        node.exps.each_with_index { |child, index| yield "exps", index, nil, child }
        node.scope.try { |child| yield "scope", nil, nil, child }
      when ClassDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
        node.superclass.try { |child| yield "superclass", nil, nil, child }
      when TraitDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
        node.supertraits.try &.each_with_index { |child, index| yield "supertraits", index, nil, child }
      when Recover
        yield "exp", nil, nil, node.exp
        node.default.try { |child| yield "default", nil, nil, child }
      when AssocTypeDecl
        node.value.try { |child| yield "value", nil, nil, child }
      when ImplDef
        yield "trait", nil, nil, node.trait
        yield "target", nil, nil, node.target
        yield "body", nil, nil, node.body
        node.trait_args.try &.each_with_index { |child, index| yield "trait_args", index, nil, child }
        node.type_var_bounds.try &.each { |key, child| yield "type_var_bounds", nil, key, child }
        node.assoc_types.try &.each { |key, child| yield "assoc_types", nil, key, child }
      when ModuleHeader, ImportDecl, UsingDecl
        # Their names and paths are ordered string fields.
      when ModuleDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
      when AnnotationDef
        yield "name", nil, nil, node.name
      when TypeDeclaration
        yield "var", nil, nil, node.var
        yield "declared_type", nil, nil, node.declared_type
        node.value.try { |child| yield "value", nil, nil, child }
      when UninitializedVar
        yield "var", nil, nil, node.var
        yield "declared_type", nil, nil, node.declared_type
      when ProcLiteral
        yield "def", nil, nil, node.def
      when ProcPointer
        node.obj.try { |child| yield "obj", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
      when Include, Extend, Metaclass
        yield "name", nil, nil, node.name
      when LibDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
      when FunDef
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.return_type.try { |child| yield "return_type", nil, nil, child }
        node.body.try { |child| yield "body", nil, nil, child }
      when TypeDef
        yield "type_spec", nil, nil, node.type_spec
      when CStructOrUnionDef
        yield "body", nil, nil, node.body
      when EnumDef
        yield "name", nil, nil, node.name
        node.base_type.try { |child| yield "base_type", nil, nil, child }
        node.members.each_with_index { |child, index| yield "members", index, nil, child }
      when ExternalVar
        yield "type_spec", nil, nil, node.type_spec
      when Alias
        yield "name", nil, nil, node.name
        yield "value", nil, nil, node.value
      when Cast, NilableCast
        yield "obj", nil, nil, node.obj
        yield "to", nil, nil, node.to
      when MacroExpression
        yield "exp", nil, nil, node.exp
      when MacroIf
        yield "cond", nil, nil, node.cond
        yield "then", nil, nil, node.then
        yield "else", nil, nil, node.else
      when MacroFor
        node.vars.each_with_index { |child, index| yield "vars", index, nil, child }
        yield "exp", nil, nil, node.exp
        yield "body", nil, nil, node.body
      when MacroVar
        node.exps.try &.each_with_index { |child, index| yield "exps", index, nil, child }
      when Asm
        node.outputs.try &.each_with_index { |child, index| yield "outputs", index, nil, child }
        node.inputs.try &.each_with_index { |child, index| yield "inputs", index, nil, child }
      when AsmOperand
        yield "exp", nil, nil, node.exp
      else
        raise ArgumentError.new("unclassified direct AST child fields for #{node.class}")
      end
    end
  end

  # Name occurrences come from stored syntax fields, never from the selected
  # contributor list. Evidence and field presence must be encoded separately.
  module DiagnosticDirectNameFields
    def self.each(node : ASTNode, & : String, Int32?, String?, String ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified direct AST node #{class_name}")
      end
      case node
      when Path
        node.names.each_with_index { |name, index| yield "names", index, nil, name }
      when Arg
        yield "name", nil, nil, node.name
        yield "external_name", nil, nil, node.external_name
      when SymbolLiteral
        yield "value", nil, nil, node.value
      when NamedArgument, Var, InstanceVar, ClassVar, Global, ReadInstanceVar, Call, Macro, RespondsTo,
           AssocTypeDecl, ProcPointer, TypeDef, CStructOrUnionDef, MacroVar
        yield "name", nil, nil, node.name
      when OpAssign
        yield "op", nil, nil, node.op
      when NamedTupleLiteral
        node.entries.each_with_index { |entry, index| yield "entries.key", index, nil, entry.key }
      when Def
        yield "name", nil, nil, node.name
        node.free_vars.try &.each_with_index { |name, index| yield "free_vars", index, nil, name }
        node.free_var_bounds.try &.each { |key, _| yield "free_var_bounds.key", nil, key, key }
        node.where_bounds.try &.each { |key, _| yield "where_bounds.key", nil, key, key }
      when ClassDef, ModuleDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
      when TraitDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
        node.assoc_types.try &.each_with_index { |name, index| yield "assoc_types", index, nil, name }
      when ImplDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
        node.type_var_bounds.try &.each { |key, _| yield "type_var_bounds.key", nil, key, key }
        node.assoc_types.try &.each { |key, _| yield "assoc_types.key", nil, key, key }
      when ModuleHeader
        node.path.each_with_index { |name, index| yield "path", index, nil, name }
      when ImportDecl, UsingDecl
        node.path.each_with_index { |name, index| yield "path", index, nil, name }
        node.names.try &.each_with_index { |name, index| yield "names", index, nil, name }
      when Rescue
        node.name.try { |name| yield "name", nil, nil, name }
      when FunDef
        yield "name", nil, nil, node.name
        yield "real_name", nil, nil, node.real_name
      when ExternalVar
        yield "name", nil, nil, node.name
        node.real_name.try { |name| yield "real_name", nil, nil, name }
      when Nop, NilLiteral, ImplicitObj, Self, Underscore, Expressions, BoolLiteral, NumberLiteral,
           CharLiteral, StringLiteral, MacroLiteral, StringInterpolation, ArrayLiteral,
           HashLiteral, RangeLiteral, RegexLiteral, TupleLiteral, Block, If, Unless, Assign, MultiAssign,
           And, Or, ProcNotation, Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out,
           MacroVerbatim, Splat, DoubleSplat, OffsetOf, VisibilityModifier, IsA, Require, When, Case,
           Select, While, Until, ExceptionHandler, Return, Break, Next, Yield, Propagate, Defer, Recover,
           AnnotationDef, Generic, TypeDeclaration, UninitializedVar, ProcLiteral, Union, Include, Extend,
           LibDef, EnumDef, Alias, Metaclass, Cast, NilableCast, TypeOf, Annotation, MacroExpression,
           MacroIf, MacroFor, MagicConstant, Asm, AsmOperand
        # These nodes have no direct string name fields. Child nodes are
        # enumerated separately by DiagnosticDirectChildFields.
      else
        raise ArgumentError.new("unclassified direct AST name fields for #{class_name}")
      end
    end
  end

  enum DiagnosticFieldPresence
    Absent
    Empty
    Nonempty
    Present
  end

  # Presence reader for the listed field families only. Unsupported kinds
  # fail explicitly rather than acquiring guessed presence semantics.
  module DiagnosticDirectPresenceFields
    private def self.collection(value : Array(T)?) : DiagnosticFieldPresence forall T
      return DiagnosticFieldPresence::Absent unless value
      value.empty? ? DiagnosticFieldPresence::Empty : DiagnosticFieldPresence::Nonempty
    end

    private def self.collection(value : Hash(K, V)?) : DiagnosticFieldPresence forall K, V
      return DiagnosticFieldPresence::Absent unless value
      value.empty? ? DiagnosticFieldPresence::Empty : DiagnosticFieldPresence::Nonempty
    end

    private def self.optional(value) : DiagnosticFieldPresence
      value.nil? ? DiagnosticFieldPresence::Absent : DiagnosticFieldPresence::Present
    end

    def self.each(node : ASTNode, & : String, DiagnosticFieldPresence ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified presence AST node #{class_name}")
      end
      case node
      when Path
        yield "names", collection(node.names)
        {"global", "visibility", "exported"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when Generic
        yield "name", DiagnosticFieldPresence::Present
        yield "type_vars", collection(node.type_vars)
        yield "named_args", collection(node.named_args)
        yield "suffix", DiagnosticFieldPresence::Present
      when Union
        yield "types", collection(node.types)
        yield "parens", DiagnosticFieldPresence::Present
      when TypeOf
        yield "expressions", collection(node.expressions)
      when ProcNotation
        yield "inputs", collection(node.inputs)
        yield "output", optional(node.output)
      when NamedArgument
        yield "name", DiagnosticFieldPresence::Present
        yield "value", DiagnosticFieldPresence::Present
      when Arg
        yield "name", DiagnosticFieldPresence::Present
        yield "external_name", DiagnosticFieldPresence::Present
        yield "default_value", optional(node.default_value)
        yield "restriction", optional(node.restriction)
        yield "parsed_annotations", collection(node.parsed_annotations)
        yield "doc", optional(node.doc)
      when Def
        yield "name", DiagnosticFieldPresence::Present
        yield "free_vars", collection(node.free_vars)
        yield "free_var_bounds", collection(node.free_var_bounds)
        yield "where_bounds", collection(node.where_bounds)
        yield "receiver", optional(node.receiver)
        yield "args", collection(node.args)
        yield "double_splat", optional(node.double_splat)
        yield "body", DiagnosticFieldPresence::Present
        yield "block_arg", optional(node.block_arg)
        yield "return_type", optional(node.return_type)
        yield "block_arity", optional(node.block_arity)
        yield "splat_index", optional(node.splat_index)
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
        {"visibility", "exported", "iyi_from_impl", "macro_def", "abstract", "calls_super",
         "calls_initialize", "calls_previous_def", "uses_block_arg", "assigns_special_var"}.each do |field|
          yield field, DiagnosticFieldPresence::Present
        end
      when Annotation
        yield "path", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "named_args", collection(node.named_args)
        yield "doc", optional(node.doc)
        yield "iyi_file_mark", DiagnosticFieldPresence::Present
      when SymbolLiteral
        yield "value", DiagnosticFieldPresence::Present
      when And, Or
        yield "left", DiagnosticFieldPresence::Present
        yield "right", DiagnosticFieldPresence::Present
      when Expressions
        yield "expressions", collection(node.expressions)
        yield "keyword", DiagnosticFieldPresence::Present
      when BoolLiteral, CharLiteral, StringLiteral, MacroLiteral
        yield "value", DiagnosticFieldPresence::Present
      when NumberLiteral
        yield "value", DiagnosticFieldPresence::Present
        yield "kind", DiagnosticFieldPresence::Present
      when StringInterpolation
        yield "expressions", collection(node.expressions)
        yield "heredoc_indent", DiagnosticFieldPresence::Present
      when ArrayLiteral
        yield "elements", collection(node.elements)
        yield "of", optional(node.of)
        yield "name", optional(node.name)
      when TupleLiteral
        yield "elements", collection(node.elements)
      when HashLiteral
        yield "entries", collection(node.entries)
        yield "of", optional(node.of)
        yield "name", optional(node.name)
      when NamedTupleLiteral
        yield "entries", collection(node.entries)
      when RangeLiteral
        {"from", "to", "exclusive"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when RegexLiteral
        {"value", "options"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when Var
        yield "name", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when InstanceVar, ClassVar, Global
        yield "name", DiagnosticFieldPresence::Present
      when ReadInstanceVar
        yield "obj", DiagnosticFieldPresence::Present
        yield "name", DiagnosticFieldPresence::Present
      when Block
        yield "args", collection(node.args)
        yield "body", DiagnosticFieldPresence::Present
        yield "splat_index", optional(node.splat_index)
        yield "unpacks", collection(node.unpacks)
      when Call
        yield "obj", optional(node.obj)
        yield "name", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "named_args", collection(node.named_args)
        yield "block", optional(node.block)
        yield "block_arg", optional(node.block_arg)
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
        yield "iyi_after_floor_div", optional(node.iyi_after_floor_div)
        {"visibility", "global", "expansion", "args_in_brackets", "has_parentheses", "iyi_group", "iyi_banged"}.each do |field|
          yield field, DiagnosticFieldPresence::Present
        end
      when If, Unless
        {"cond", "then", "else"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "else_location", optional(node.else_location)
        yield "ternary", DiagnosticFieldPresence::Present if node.is_a?(If)
      when Assign
        yield "target", DiagnosticFieldPresence::Present
        yield "value", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when OpAssign
        {"target", "value", "op"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "name_location", optional(node.name_location)
      when MultiAssign
        yield "targets", collection(node.targets)
        yield "values", collection(node.values)
      when Nop, NilLiteral, ImplicitObj, Self, Underscore
        # No syntax-specific stored fields.
      else
        raise ArgumentError.new("unclassified AST presence fields for #{class_name}")
      end
    end
  end

  alias DiagnosticScalarFieldValue = Bool | Int32 | String | Nil

  # Direct scalar reader for the listed kinds. Type tags distinguish enum
  # names, integer optionals, booleans and arbitrary-byte strings.
  module DiagnosticDirectScalarFields
    def self.each(node : ASTNode, & : String, String, DiagnosticScalarFieldValue ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified scalar AST node #{class_name}")
      end
      case node
      when Path
        yield "global", "bool", node.global?
        yield "visibility", "Visibility", node.visibility.to_s
        yield "exported", "bool", node.exported?
      when Generic
        yield "suffix", "Generic::Suffix", node.suffix.to_s
      when Union
        yield "parens", "bool", node.parens?
      when Arg
        yield "doc", "bytes?", node.doc
      when Def
        yield "block_arity", "int32?", node.block_arity
        yield "splat_index", "int32?", node.splat_index
        yield "doc", "bytes?", node.doc
        yield "visibility", "Visibility", node.visibility.to_s
        yield "exported", "bool", node.exported?
        yield "iyi_from_impl", "bool", node.iyi_from_impl?
        yield "macro_def", "bool", node.macro_def?
        yield "abstract", "bool", node.abstract?
        yield "calls_super", "bool", node.calls_super?
        yield "calls_initialize", "bool", node.calls_initialize?
        yield "calls_previous_def", "bool", node.calls_previous_def?
        yield "uses_block_arg", "bool", node.uses_block_arg?
        yield "assigns_special_var", "bool", node.assigns_special_var?
      when Annotation
        yield "doc", "bytes?", node.doc
        yield "iyi_file_mark", "bool", node.iyi_file_mark?
      when Expressions
        yield "keyword", "Expressions::Keyword", node.keyword.to_s
      when BoolLiteral
        yield "value", "bool", node.value
      when NumberLiteral
        yield "value", "bytes", node.value
        yield "kind", "NumberKind", node.kind.to_s
      when CharLiteral
        yield "value", "char", node.value.ord
      when StringLiteral, MacroLiteral
        yield "value", "bytes", node.value
      when StringInterpolation
        yield "heredoc_indent", "int32", node.heredoc_indent
      when RangeLiteral
        yield "exclusive", "bool", node.exclusive?
      when RegexLiteral
        yield "options", "RegexOptions", node.options.value.to_i32
      when Var
        yield "doc", "bytes?", node.doc
      when Block
        yield "splat_index", "int32?", node.splat_index
      when Call
        yield "doc", "bytes?", node.doc
        yield "visibility", "Visibility", node.visibility.to_s
        yield "global", "bool", node.global?
        yield "expansion", "bool", node.expansion?
        yield "args_in_brackets", "bool", node.args_in_brackets?
        yield "has_parentheses", "bool", node.has_parentheses?
        yield "iyi_group", "bool", node.iyi_group?
        yield "iyi_banged", "bool", node.iyi_banged?
      when If
        yield "ternary", "bool", node.ternary?
      when Assign
        yield "doc", "bytes?", node.doc
      when ArrayLiteral, TupleLiteral, HashLiteral, NamedTupleLiteral, InstanceVar, ClassVar, Global,
           ReadInstanceVar, Unless, OpAssign, MultiAssign
        # Their syntax-specific fields are names, children, or collections.
      when TypeOf, ProcNotation, NamedArgument, SymbolLiteral, And, Or, Nop, NilLiteral, ImplicitObj, Self, Underscore
        # Their syntax-specific fields are names, children, or collections.
      else
        raise ArgumentError.new("unclassified AST scalar fields for #{class_name}")
      end
    end
  end

  record DiagnosticInventoryStep, field : String, index : Int32?, map_key : String? do
    def initialize(@field : String, @index : Int32?, @map_key : String?)
      raise ArgumentError.new("empty inventory field") if @field.empty?
      raise ArgumentError.new("negative inventory index") if @index.try { |index| index < 0 }
      raise ArgumentError.new("ambiguous inventory coordinate") if @index && @map_key
    end
  end

  # Bounded partial syntax inventory. Unsupported presence or scalar readers
  # refuse capture. It is not a registry: parser acceptance, complete field
  # coverage, source-witness binding and authority still need validation.
  class DiagnosticAstInventorySnapshot
    MAX_BYTES = 8_i64 * 1024 * 1024
    MAX_DEPTH = 128
    getter sha256 : String
    @bytes : String
    @active = Set(UInt64).new
    @evidence_budget : UInt64 = DiagnosticOrigin::MAX_UNFOLDED_BYTES

    def initialize(root : ASTNode)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      write_node(json, root, 0)
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      @bytes.dup
    end

    # Resolves only the inventory's own name bytes. It cannot establish source
    # provenance or authorize a transformed artifact.
    def resolve_name(owner_path : Array(DiagnosticInventoryStep), field : DiagnosticInventoryStep) : Bytes
      raise ArgumentError.new("inventory path exceeds depth limit") if owner_path.size > MAX_DEPTH
      parser = JSON::Parser.new(@bytes)
      parser.max_nesting = 1024
      node = parser.parse
      owner_path.each do |step|
        node = find_coordinate(node["children"].as_a, step)["node"]
      end
      encoded = find_coordinate(node["names"].as_a, field)["value_base64"].as_s
      Base64.decode(encoded)
    end

    private def find_coordinate(entries : Array(JSON::Any), step : DiagnosticInventoryStep) : JSON::Any
      encoded_key = encode_key(step.map_key)
      found : JSON::Any? = nil
      entries.each do |entry|
        next unless entry["field"].as_s == step.field
        next unless entry["index"].as_i? == step.index
        next unless entry["map_key_base64"].as_s? == encoded_key
        raise ArgumentError.new("ambiguous inventory coordinate") if found
        found = entry
      end
      found || raise ArgumentError.new("unknown inventory coordinate")
    end

    private def write_node(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("AST inventory exceeds depth limit") if depth > MAX_DEPTH
      id = node.object_id
      raise ArgumentError.new("cyclic AST inventory") unless @active.add?(id)
      begin
        json.object do
          json.field "kind", node.class.name
          json.field("presence") { write_presence(json, node) }
          json.field("scalars") { write_scalars(json, node) }
          json.field("location") { write_stored_location(json, node.diagnostic_stored_location) }
          json.field("end_location") { write_stored_location(json, node.diagnostic_stored_end_location) }
          json.field("extra_locations") { write_extra_locations(json, node) }
          if origin = node.diagnostic_origin
            charge_evidence(origin.graph_bytes, origin.graph_depth, depth)
          end
          json.field "origin", node.diagnostic_origin
          json.field "macro_lineage", node.diagnostic_macro_lineage.to_s
          json.field("name_slots") { write_name_slots(json, node, depth) }
          json.field("literal_names") { write_literal_names(json, node, depth) }
          json.field("literal_productions") { write_literal_productions(json, node) }
          json.field "names" do
            json.array do
              DiagnosticDirectNameFields.each(node) do |field, index, key, value|
                raise ArgumentError.new("AST inventory name exceeds size limit") if value.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
                json.object do
                  json.field "field", field
                  json.field "index", index
                  json.field "map_key_base64", encode_key(key)
                  json.field "value_base64", Base64.strict_encode(value.to_slice)
                end
              end
            end
          end
          json.field "children" do
            json.array do
              DiagnosticDirectChildFields.each(node) do |field, index, key, child|
                json.object do
                  json.field "field", field
                  json.field "index", index
                  json.field "map_key_base64", encode_key(key)
                  json.field("node") { write_node(json, child, depth + 1) }
                end
              end
            end
          end
        end
      ensure
        @active.delete(id)
      end
    end

    private def write_presence(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        DiagnosticDirectPresenceFields.each(node) do |field, state|
          json.object do
            json.field "field", field
            json.field "state", state.to_s
          end
        end
      end
    end

    private def write_scalars(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        DiagnosticDirectScalarFields.each(node) do |field, type, value|
          json.object do
            json.field "field", field
            json.field "type", type
            json.field "value" do
              case value
              when Nil
                json.null
              when Bool
                json.bool(value)
              when Int32
                json.number(value)
              when String
                if value.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
                  raise ArgumentError.new("AST scalar exceeds size limit")
                end
                json.string(Base64.strict_encode(value.to_slice))
              else
                raise ArgumentError.new("unclassified AST scalar value")
              end
            end
          end
        end
      end
    end

    private def write_extra_locations(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        case node
        when Def
          write_named_location(json, "name_location", node.name_location)
        when Call
          write_named_location(json, "name_location", node.name_location)
          write_named_location(json, "iyi_after_floor_div", node.iyi_after_floor_div)
        when If, Unless
          write_named_location(json, "else_location", node.else_location)
        when OpAssign
          write_named_location(json, "name_location", node.name_location)
        when Path, Generic, Union, TypeOf, ProcNotation, NamedArgument, Arg, Annotation,
             SymbolLiteral, And, Or, Nop, NilLiteral, ImplicitObj, Self, Underscore,
             Expressions, BoolLiteral, CharLiteral, StringLiteral, MacroLiteral, NumberLiteral,
             StringInterpolation, ArrayLiteral, TupleLiteral, HashLiteral, NamedTupleLiteral,
             RangeLiteral, RegexLiteral, Var, InstanceVar, ClassVar, Global, ReadInstanceVar,
             Block, Assign, MultiAssign
          # These kinds have no additional location field in their syntax schema.
        else
          raise ArgumentError.new("unclassified AST extra location fields for #{node.class}")
        end
      end
    end

    private def write_named_location(json : JSON::Builder, field : String, location : Location?) : Nil
      json.object do
        json.field "field", field
        json.field("value") { write_stored_location(json, location) }
      end
    end

    private def write_stored_location(json : JSON::Builder, location : Location?) : Nil
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

    private def charge_evidence(bytes : UInt64, graph_depth : Int32, depth : Int32) : Nil
      if graph_depth.to_i64 + depth > MAX_DEPTH || bytes > @evidence_budget
        raise ArgumentError.new("AST inventory evidence exceeds graph limit")
      end
      @evidence_budget -= bytes
    end

    private def write_name_slots(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      count = node.diagnostic_name_slots_count
      unless count
        json.null
        return
      end
      if node.diagnostic_name_slots_graph_bytes > @evidence_budget
        raise ArgumentError.new("AST inventory name evidence exceeds graph limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, depth)
      slots = [] of {DiagnosticNameSlot, Indexable(DiagnosticNameValue)}
      node.each_diagnostic_name_slot do |slot, values|
        charge_evidence(values.size.to_u64 * 32_u64, 0, depth)
        slots << {slot, values}
      end
      json.array do
        slots.sort_by { |entry| {entry[0].kind.value, entry[0].index} }.each do |slot, values|
          json.object do
            json.field "kind", slot.kind.to_s
            json.field "index", slot.index
            json.field "values" do
              json.array do
                values.each do |value|
                  case value
                  when DiagnosticNameValue::Observed
                    token = value.source_token
                    graph_depth = token.lexical_origin.graph_depth
                    if binding = token.binding_origin
                      graph_depth = Math.max(graph_depth, binding.graph_depth)
                    end
                    charge_evidence(value.graph_bytes, graph_depth, depth)
                  when DiagnosticNameValue::Derived
                    charge_evidence(value.graph_bytes, value.origin.graph_depth, depth)
                  else
                    raise ArgumentError.new("unclassified AST name evidence")
                  end
                  value.to_json(json)
                end
              end
            end
          end
        end
      end
    end

    private def write_literal_names(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      count = node.diagnostic_literal_names_count
      unless count
        json.null
        return
      end
      if node.diagnostic_literal_names_encoded_bytes > MAX_BYTES.to_u64
        raise ArgumentError.new("AST inventory literal evidence exceeds size limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, depth)
      names = [] of {{String, Int32}, DiagnosticParsedLiteral}
      node.each_diagnostic_literal_name { |key, literal| names << {key, literal} }
      json.array do
        names.sort_by { |entry| entry[0] }.each do |key, literal|
          json.object do
            json.field "field", key[0]
            json.field "index", key[1]
            json.field "input_sha256", literal.input_sha256
            json.field "input_bytesize", literal.input_bytesize
            json.field "lexical_mode", literal.lexical_mode
            json.field "decoded_base64", literal.decoded_base64
            json.field "segments" do
              json.array do
                charge_evidence(literal.segments_count.to_u64 * 32_u64, 0, depth)
                literal.each_segment do |segment|
                  json.object do
                    json.field "start", segment.start_offset
                    json.field "end", segment.end_offset
                    json.field "raw_base64", segment.raw_base64
                  end
                end
              end
            end
            json.field "expansion" do
              if expansion = literal.expansion
                charge_evidence(expansion[0].graph_bytes, expansion[0].graph_depth, depth)
                charge_evidence(expansion[1].graph_bytes, expansion[1].graph_depth, depth)
                json.object do
                  json.field "invocation", expansion[0]
                  json.field "definition", expansion[1]
                  json.field "guard", expansion[2]
                end
              else
                json.null
              end
            end
          end
        end
      end
    end

    private def write_literal_productions(json : JSON::Builder, node : ASTNode) : Nil
      count = node.diagnostic_literal_productions_count
      unless count
        json.null
        return
      end
      if node.diagnostic_literal_productions_raw_bytes > MAX_BYTES.to_u64
        raise ArgumentError.new("AST inventory literal production exceeds size limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, 0)
      productions = [] of {{String, Int32}, Indexable(DiagnosticLiteralProductionSegment)}
      node.each_diagnostic_literal_production do |key, segments|
        charge_evidence(segments.size.to_u64 * 32_u64, 0, 0)
        productions << {key, segments}
      end
      json.array do
        productions.sort_by { |entry| entry[0] }.each do |key, segments|
          json.object do
            json.field "field", key[0]
            json.field "index", key[1]
            json.field "segments" do
              json.array do
                segments.each do |segment|
                  json.object do
                    json.field "production", segment.production.to_s
                    json.field "start", segment.start_offset
                    json.field "end", segment.end_offset
                    json.field "raw_base64", segment.raw_base64
                    json.field "delimiter_kind", segment.delimiter_kind
                    json.field "nest", segment.nest
                    json.field "end_delimiter", segment.end_delimiter
                    json.field "allow_escapes", segment.allow_escapes
                    json.field "witnesses" do
                      json.array do
                        charge_evidence(segment.witnesses_count.to_u64 * 32_u64, 0, 0)
                        segment.each_witness do |witness|
                          json.object do
                            json.field "kind", witness.kind.to_s
                            json.field "start", witness.start_offset
                            json.field "end", witness.end_offset
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

    private def encode_key(key : String?) : String?
      return nil unless key
      raise ArgumentError.new("AST inventory key exceeds size limit") if key.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
      Base64.strict_encode(key.to_slice)
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

    def witnesses_count : Int32
      @witnesses.size
    end

    def each_witness(& : DiagnosticLiteralWitness ->) : Nil
      @witnesses.each { |witness| yield witness }
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

    def segments_count : Int32
      @segments.size
    end

    def each_segment(& : DiagnosticLiteralSegment ->) : Nil
      @segments.each { |segment| yield segment }
    end

    # Validates canonical RFC 4648 base64 without allocating decoded bytes.
    def decoded_bytesize : Int32
      encoded = @decoded_base64
      size = encoded.bytesize
      raise ArgumentError.new("literal decoded value exceeds size limit") if size.to_u64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES
      raise ArgumentError.new("invalid literal base64 length") unless size % 4 == 0
      return 0 if size == 0
      padding = encoded.byte_at(size - 1) == 61_u8 ? 1 : 0
      padding += 1 if padding == 1 && encoded.byte_at(size - 2) == 61_u8
      (0...(size - padding)).each do |index|
        raise ArgumentError.new("invalid literal base64 alphabet") unless base64_value(encoded.byte_at(index))
      end
      if padding > 0
        value = base64_value(encoded.byte_at(size - padding - 1))
        raise ArgumentError.new("invalid literal base64 padding") unless value
        mask = padding == 2 ? 15 : 3
        raise ArgumentError.new("noncanonical literal base64 padding") unless (value & mask) == 0
      end
      (size // 4) * 3 - padding
    end

    private def base64_value(byte : UInt8) : Int32?
      case byte
      when 65_u8..90_u8  then byte.to_i - 65
      when 97_u8..122_u8 then byte.to_i - 97 + 26
      when 48_u8..57_u8  then byte.to_i - 48 + 52
      when 43_u8         then 62
      when 47_u8         then 63
      else                    nil
      end
    end
  end

  # Checks byte binding only. Production semantics, owner coordinates and
  # expansion ancestry still require the complete registry validator.
  module DiagnosticLiteralInputChecks
    def self.verify_input_bytes!(literal : DiagnosticParsedLiteral,
                                 productions : Indexable(DiagnosticLiteralProductionSegment),
                                 expected_value : String, input : AcceptedCaptureInput) : Nil
      unless literal.input_sha256 == input.input_sha256 &&
             literal.input_bytesize == input.input_bytesize &&
             literal.lexical_mode == input.lexical_mode
        raise ArgumentError.new("literal input identity mismatch")
      end
      raise ArgumentError.new("literal expansion requires expansion input binding") if literal.expansion
      max = DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
      if literal.decoded_base64.bytesize.to_i64 > max || expected_value.bytesize.to_i64 > max * 3 // 4 - 4
        raise ArgumentError.new("literal decoded value exceeds size limit")
      end
      unless literal.decoded_bytesize == expected_value.bytesize &&
             Base64.strict_encode(expected_value.to_slice) == literal.decoded_base64
        raise ArgumentError.new("literal decoded value mismatch")
      end
      raise ArgumentError.new("literal production evidence missing") if productions.empty?
      if literal.segments_count.to_i64 + productions.size.to_i64 > max // 64
        raise ArgumentError.new("literal evidence count exceeds size limit")
      end
      unless literal.segments_count == productions.size
        raise ArgumentError.new("literal constituent and production counts differ")
      end
      segment_index = 0
      literal.each_segment do |segment|
        unless input.matches_encoded_span?(segment.start_offset, segment.end_offset, segment.raw_base64)
          raise ArgumentError.new("literal constituent input bytes mismatch")
        end
        production = productions[segment_index]
        if production.production.percent_symbol_element?
          unless segment.start_offset >= production.start_offset && segment.end_offset <= production.end_offset
            raise ArgumentError.new("percent symbol constituent outside production")
          end
        elsif segment.start_offset != production.start_offset || segment.end_offset != production.end_offset
          raise ArgumentError.new("literal constituent and production span mismatch")
        end
        segment_index += 1
      end
      previous_end : Int32? = nil
      witness_total = 0_i64
      productions.each do |segment|
        unless input.matches_encoded_span?(segment.start_offset, segment.end_offset, segment.raw_base64)
          raise ArgumentError.new("literal production input bytes mismatch")
        end
        witness_total += segment.witnesses_count.to_i64
        raise ArgumentError.new("literal witnesses exceed size limit") if witness_total > max // 64
        verify_witnesses!(segment, previous_end, input.input_bytesize)
        previous_end = segment.end_offset
      end
    end

    private def self.verify_witnesses!(segment : DiagnosticLiteralProductionSegment, previous_end : Int32?,
                                       input_bytesize : Int32) : Nil
      if segment.production.symbol_token?
        count = 0
        segment.each_witness do |witness|
          count += 1
          unless witness.kind.string_piece? && witness.start_offset == segment.start_offset &&
                 witness.end_offset == segment.end_offset
            raise ArgumentError.new("invalid symbol token witness")
          end
        end
        raise ArgumentError.new("invalid symbol token witness count") unless count == 1 && previous_end.nil?
        return
      end
      unless (segment.production.delimiter? && segment.delimiter_kind == "STRING") ||
             (segment.production.percent_symbol_element? && segment.delimiter_kind == "SYMBOL_ARRAY")
        raise ArgumentError.new("invalid literal delimiter production")
      end
      raise ArgumentError.new("percent symbol cannot be continued") if segment.production.percent_symbol_element? && previous_end
      opener = false
      closer = false
      interpolation = false
      continuation = false
      cursor = segment.start_offset
      segment.each_witness do |witness|
        raise ArgumentError.new("literal witness lies outside input") if witness.end_offset > input_bytesize
        if witness.kind.continuation?
          unless previous_end && !opener && !continuation &&
                 witness.start_offset == previous_end && witness.end_offset == segment.start_offset
            raise ArgumentError.new("invalid literal continuation witness")
          end
          continuation = true
          next
        end
        unless witness.start_offset >= cursor && witness.end_offset <= segment.end_offset && !closer
          raise ArgumentError.new("unordered literal witness")
        end
        case witness.kind
        when .opener?
          raise ArgumentError.new("invalid literal opener witness") if opener || witness.start_offset != segment.start_offset
          opener = true
        when .closing_delimiter?
          unless opener && !interpolation && witness.end_offset == segment.end_offset
            raise ArgumentError.new("invalid literal closing witness")
          end
          closer = true
        when .string_piece?
          raise ArgumentError.new("string piece outside literal") unless opener && !interpolation
        when .interpolation_start?
          raise ArgumentError.new("invalid interpolation start witness") unless opener && !interpolation
          interpolation = true
        when .interpolation_end?
          raise ArgumentError.new("invalid interpolation end witness") unless interpolation
          interpolation = false
        else
          raise ArgumentError.new("unclassified literal witness")
        end
        cursor = witness.end_offset
      end
      unless opener && closer && !interpolation && (previous_end.nil? || continuation)
        raise ArgumentError.new("incomplete literal production witnesses")
      end
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
