require "json"
require "base64"
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
