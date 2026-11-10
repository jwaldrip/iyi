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
