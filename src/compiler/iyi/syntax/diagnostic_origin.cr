require "json"
require "set"
require "crystal/digest/sha256"

module Iyi
  class DiagnosticAnchor
    getter offset : Int32
    getter kind : String
    getter role : String
    getter origin : DiagnosticOrigin?
    getter event_index : Int32
    getter attachment : DiagnosticFragmentAttachment
    @name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticNameValue))

    def initialize(@offset : Int32, @kind : String, @role : String, @origin : DiagnosticOrigin?,
                   name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticNameValue)),
                   @event_index : Int32, @attachment : DiagnosticFragmentAttachment)
      @name_slots = DiagnosticNameMetadata.copy_and_validate(name_slots, @origin)
    end

    def name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticNameValue))
      DiagnosticNameMetadata.copy_and_validate(@name_slots, @origin)
    end

    def copy_with(*, offset : Int32 = @offset, event_index : Int32 = @event_index,
                  attachment : DiagnosticFragmentAttachment = @attachment) : DiagnosticAnchor
      DiagnosticAnchor.new(offset, @kind, @role, @origin, @name_slots, event_index, attachment)
    end

    def_equals_and_hash @offset, @kind, @role, @origin, @name_slots, @event_index, @attachment
  end

  record DiagnosticRegion,
    start_offset : Int32,
    end_offset : Int32,
    text_sha256 : String,
    events : Array(DiagnosticTokenEvent),
    anchors : Array(DiagnosticAnchor)

  enum DiagnosticMacroLineage
    Unknown
    Preserved
    Constructed
  end


  enum DiagnosticNameSlotKind
    Primary
    Receiver
    ExternalName
    PathSegment
    TypeParameter
    NamedEntry
    EnumMember
    WhereVariable
  end

  record DiagnosticNameSlot, kind : DiagnosticNameSlotKind, index : Int32 = 0 do
    def initialize(@kind : DiagnosticNameSlotKind, @index : Int32 = 0)
      raise ArgumentError.new("negative diagnostic name slot index") if @index < 0
      if @index != 0 && !@kind.path_segment? && !@kind.type_parameter? && !@kind.named_entry? && !@kind.where_variable?
        raise ArgumentError.new("diagnostic name slot is not indexed")
      end
    end
  end

  record DiagnosticSourceNameToken,
    lexical_origin : DiagnosticOrigin,
    binding_origin : DiagnosticOrigin?,
    context : String,
    input_sha256 : String,
    input_bytesize : Int32,
    input_start : Int32,
    input_end : Int32,
    lexical_mode : String,
    token_kind : String,
    raw_text : String do
    NAME_OPERATORS = %w(! != !~ % & &* &** &+ &- * ** + - / // < << <= <=> = == === =~ > >= >> [] []= []? ^ ` | ~)
    MACRO_OPERATORS = %w(<< < <= == === != =~ !~ >> > >= + - * / // ~ % & | ^ ** [] []? []= <=> &+ &- &* &** = `)

    def self.valid_token?(kind : String, raw : String, mode : String, context : String) : Bool
      allowed = case context
                when "method_name"                   then kind == "IDENT" || kind == "CONST" || NAME_OPERATORS.includes?(kind)
                when "definition_name"               then kind == "IDENT" || NAME_OPERATORS.includes?(kind)
                when "macro_name"                    then kind == "IDENT" || kind == "CONST" || MACRO_OPERATORS.includes?(kind)
                when "local_reference"               then kind == "IDENT"
                when "instance_variable"             then kind == "INSTANCE_VAR"
                when "class_variable"                then kind == "CLASS_VAR"
                when "parameter"                     then {"IDENT", "INSTANCE_VAR", "CLASS_VAR"}.includes?(kind)
                when "path_segment", "type_parameter", "where_variable" then kind == "CONST"
                when "named_entry"                   then {"IDENT", "CONST"}.includes?(kind)
                when "enum_member"                   then kind == "CONST"
                when "special_global"                then {"$~", "$?"}.includes?(kind)
                when "regex_match_index"             then kind == "GLOBAL_MATCH_DATA_INDEX"
                when "type_self"                    then kind == "IDENT"
                else                                      false
                end
      return false unless allowed && {"Crystal", "Iyi"}.includes?(mode) && raw.valid_encoding?
      return kind == "IDENT" && raw == "self" if context == "type_self"
      return raw == kind if context == "special_global"
      if context == "regex_match_index"
        return false unless raw.starts_with?("$")
        number = raw.byte_slice(1, raw.bytesize - 1)
        optional = number.ends_with?("?")
        number = number.byte_slice(0, number.bytesize - 1) if optional
        return false if number.empty? || (number.starts_with?("0") && (number != "0" || optional))
        return false unless number.each_byte.all? { |byte| (48_u8..57_u8).includes?(byte) }
        return !number.to_i?.nil?
      end
      return raw == kind if NAME_OPERATORS.includes?(kind)
      prefix = kind == "INSTANCE_VAR" ? "@" : (kind == "CLASS_VAR" ? "@@" : "")
      return false unless raw.starts_with?(prefix)
      name = raw.byte_slice(prefix.bytesize, raw.bytesize - prefix.bytesize)
      if kind == "IDENT" && (name.ends_with?("?") || name.ends_with?("!"))
        return false if mode == "Iyi" && name.ends_with?("!")
        name = name.byte_slice(0, name.bytesize - 1)
      end
      first = name[0]? || return false
      return false if kind == "IDENT" && (first.uppercase? || first.titlecase?)
      return false if kind == "CONST" && !(first.uppercase? || first.titlecase?)
      return false if kind == "IDENT" && raw == "_"
      name.each_char_with_index do |char, index|
        return false unless char.ascii_letter? || char == '_' || char.ord > 0x9f || (index > 0 && char.ascii_number?)
      end
      true
    end

    def initialize(@lexical_origin : DiagnosticOrigin, @binding_origin : DiagnosticOrigin?, @context : String,
                   @input_sha256 : String, @input_bytesize : Int32, @input_start : Int32, @input_end : Int32,
                   @lexical_mode : String, @token_kind : String, @raw_text : String)
      unless {"method_name", "definition_name", "macro_name", "local_reference", "instance_variable",
              "class_variable", "parameter", "path_segment", "type_parameter", "named_entry",
              "enum_member", "special_global", "regex_match_index", "where_variable", "type_self"}.includes?(@context)
        raise ArgumentError.new("invalid diagnostic name context")
      end
      unless @input_sha256.bytesize == 64 && @input_sha256.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) }
        raise ArgumentError.new("invalid diagnostic name input digest")
      end
      unless @input_start >= 0 && @input_end > @input_start && @input_end <= @input_bytesize &&
             @input_end - @input_start == @raw_text.bytesize && @raw_text.valid_encoding? &&
             {"Crystal", "Iyi"}.includes?(@lexical_mode) && !@token_kind.empty?
        raise ArgumentError.new("invalid diagnostic source name token")
      end
      unless self.class.valid_token?(@token_kind, @raw_text, @lexical_mode, @context)
        raise ArgumentError.new("invalid diagnostic name token spelling")
      end
      bytes = 256_u64 + @raw_text.bytesize.to_u64 * 6 + @token_kind.bytesize.to_u64 * 6 + @context.bytesize.to_u64 * 6
      [@lexical_origin, @binding_origin].each do |origin|
        next unless origin
        raise ArgumentError.new("diagnostic name graph exceeds depth limit") if origin.graph_depth + 1 > DiagnosticOrigin::MAX_DEPTH
        raise ArgumentError.new("diagnostic name graph exceeds size limit") if bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES || origin.graph_bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES - bytes
        bytes += origin.graph_bytes
      end
      raise ArgumentError.new("diagnostic name graph exceeds size limit") if bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES
      unless @lexical_origin.valid_for_anchor?("Name", @context) ||
             ({"method_name", "local_reference"}.includes?(@context) && @lexical_origin.valid_for_anchor?("Call", "method"))
        raise ArgumentError.new("name lexical origin has incompatible role")
      end
      case lexical_origin = @lexical_origin
      when DiagnosticOrigin::Written
        raise ArgumentError.new("name token origin offset mismatch") unless lexical_origin.input_byte_offset == @input_start
      when DiagnosticOrigin::Expanded
        event = lexical_origin.token_event
        unless event.input_start == @input_start && event.input_end == @input_end &&
               event.selection.whole? && event.token_kind == @token_kind && event.token_text == @raw_text &&
               event.lexical_mode == @lexical_mode && lexical_origin.expansion_guard == "sha256:#{@input_sha256}"
          raise ArgumentError.new("name token expansion input mismatch")
        end
      else
        raise ArgumentError.new("invalid name lexical origin")
      end
      if binding = @binding_origin
        unless binding.is_a?(DiagnosticOrigin::Synthetic) && binding.synthesis_kind == "local_binding" &&
               binding.structural_slot == "assignment" && binding.parent_origin == @lexical_origin
          raise ArgumentError.new("invalid name binding origin")
        end
      end
    end

    def graph_bytes : UInt64
      bytes = 256_u64 + @raw_text.bytesize.to_u64 * 6 + @token_kind.bytesize.to_u64 * 6 + @context.bytesize.to_u64 * 6
      bytes += @lexical_origin.graph_bytes
      bytes += @binding_origin.not_nil!.graph_bytes if @binding_origin
      bytes
    end

    def to_json(json : JSON::Builder) : Nil
      json.object do
        json.field "lexical_origin", @lexical_origin
        json.field "binding_origin", @binding_origin
        json.field "context", @context
        json.field "input_sha256", @input_sha256
        json.field "input_bytesize", @input_bytesize
        json.field "input_start", @input_start
        json.field "input_end", @input_end
        json.field "lexical_mode", @lexical_mode
        json.field "token_kind", @token_kind
        json.field "raw_text", @raw_text
      end
    end
  end

  enum DiagnosticTypeSugar : UInt8
    Pointer = 1
    DoublePointer = 2
    NilableType = 3
    NilableExpression = 4
    SelfNilableType = 5
    StaticArray = 6
    Tuple = 7
    NamedTuple = 8
    NilPredicate = 9
  end
  enum DiagnosticTypeSugarResult : UInt8
    Pointer = 1
    Union = 2
    Nil = 3
    StaticArray = 4
    Tuple = 5
    NamedTuple = 6
    Self = 7
  end

  record DiagnosticSourceSyntaxToken,
    lexical_origin : DiagnosticOrigin,
    input_sha256 : String,
    input_bytesize : Int32,
    input_start : Int32,
    input_end : Int32,
    lexical_mode : String,
    token_kind : String,
    raw_text : String do
    def initialize(@lexical_origin : DiagnosticOrigin, @input_sha256 : String, @input_bytesize : Int32,
                   @input_start : Int32, @input_end : Int32, @lexical_mode : String, @token_kind : String, @raw_text : String)
      unless @input_sha256.bytesize == 64 && @input_sha256.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) } &&
             @input_start >= 0 && @input_end > @input_start && @input_end <= @input_bytesize &&
             @input_end - @input_start == @raw_text.bytesize && @raw_text.valid_encoding? &&
             {"Crystal", "Iyi"}.includes?(@lexical_mode) &&
             (({"*", "**", "?", "[", "]", "{", "}"}.includes?(@raw_text) && @token_kind == @raw_text) ||
              (@token_kind == "IDENT" && {"self?", "nil?"}.includes?(@raw_text))) &&
             @lexical_origin.valid_for_anchor?("TypeSyntax", "token")
        raise ArgumentError.new("invalid observed type-syntax token")
      end
      case origin = @lexical_origin
      when DiagnosticOrigin::Written
        raise ArgumentError.new("type-syntax token offset mismatch") unless origin.input_byte_offset == @input_start
      when DiagnosticOrigin::Expanded
        event = origin.token_event
        unless event.input_start == @input_start && event.input_end == @input_end &&
               event.selection.whole? && event.token_kind == @token_kind && event.token_text == @raw_text &&
               event.lexical_mode == @lexical_mode && origin.expansion_guard == "sha256:#{@input_sha256}"
          raise ArgumentError.new("type-syntax expansion mismatch")
        end
      else
        raise ArgumentError.new("invalid type-syntax origin")
      end
      raise ArgumentError.new("type-syntax origin graph too large") if @lexical_origin.graph_bytes + @raw_text.bytesize.to_u64 * 6 + 256_u64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES
    end

    def to_json(json : JSON::Builder) : Nil
      json.object do
        json.field "lexical_origin", @lexical_origin
        json.field "input_sha256", @input_sha256
        json.field "input_bytesize", @input_bytesize
        json.field "input_start", @input_start
        json.field "input_end", @input_end
        json.field "lexical_mode", @lexical_mode
        json.field "token_kind", @token_kind
        json.field "raw_text", @raw_text
      end
    end
  end

  enum DiagnosticBoundProducerKind : UInt8
    StripRoot = 1
    ForeignType = 2
    AliasType = 3
    SelfReturn = 4
    SemanticSignatureType = 5
    UninitializedClassVar = 6
    ConstantAccessor = 7
  end

  record DiagnosticBoundNameSource, start_offset : Int32, end_offset : Int32, name : DiagnosticNameValue do
    def to_json(json : JSON::Builder) : Nil
      json.object do
        json.field "start_offset", start_offset
        json.field "end_offset", end_offset
        json.field "name", name
      end
    end
  end

  record DiagnosticBoundProjectionData,
    producer : DiagnosticBoundProducer,
    source_fragment_sha256 : String,
    source_text : String,
    source_names : Array(DiagnosticBoundNameSource),
    output_text : String,
    lexical_mode : String,
    result_start : Int32,
    result_end : Int32,
    token_kind : String,
    context : String

  abstract class DiagnosticBoundProducer
    def to_json(json : JSON::Builder) : Nil
      json.object do
        case self
        when StripRoot
          json.field "kind", "StripRoot"
          json.field "root", self.root
        when ForeignType
          json.field "kind", "ForeignType"
          json.field "module_name", self.module_name
          json.field "source_name", self.source_name
          json.field "qualified_name", self.qualified_name
        when AliasType
          json.field "kind", "AliasType"
          json.field "owner", self.owner
          json.field "name", self.name
          json.field "resolved_type", self.resolved_type
        when SelfReturn
          json.field "kind", "SelfReturn"
          json.field "owner_type", self.owner_type
          json.field "method_name", self.method_name
          json.field "receiver", self.receiver
        when SemanticSignatureType
          json.field "kind", "SemanticSignatureType"
          json.field "definition_origin", self.definition_origin
          json.field "field", self.field
          json.field "parameter_index", self.parameter_index
          json.field "semantic_type", self.semantic_type
        when UninitializedClassVar
          json.field "kind", "UninitializedClassVar"
          json.field "declaration_origin", self.declaration_origin
          json.field "owner_type", self.owner_type
          json.field "variable_name", self.variable_name
          json.field "semantic_type", self.semantic_type
        when ConstantAccessor
          json.field "kind", "ConstantAccessor"
          json.field "definition_origin", self.definition_origin
          json.field "prefix", self.prefix
          json.field "constant_name", self.constant_name
          json.field "part", self.part
        end
      end
    end
    class StripRoot < DiagnosticBoundProducer
      getter root : String
      def initialize(@root : String); end
      def_equals_and_hash @root
    end
    class ForeignType < DiagnosticBoundProducer
      getter module_name : String
      getter source_name : String
      getter qualified_name : String
      def initialize(@module_name : String, @source_name : String, @qualified_name : String); end
      def_equals_and_hash @module_name, @source_name, @qualified_name
    end
    class AliasType < DiagnosticBoundProducer
      getter owner : String
      getter name : String
      getter resolved_type : String
      def initialize(@owner : String, @name : String, @resolved_type : String); end
      def_equals_and_hash @owner, @name, @resolved_type
    end
    class SelfReturn < DiagnosticBoundProducer
      getter owner_type : String
      getter method_name : String
      getter receiver : String
      def initialize(@owner_type : String, @method_name : String, @receiver : String); end
      def_equals_and_hash @owner_type, @method_name, @receiver
    end
    class SemanticSignatureType < DiagnosticBoundProducer
      getter definition_origin : DiagnosticOrigin
      getter field : String
      getter parameter_index : Int32?
      getter semantic_type : String
      def initialize(@definition_origin : DiagnosticOrigin, @field : String, @parameter_index : Int32?, @semantic_type : String); end
      def_equals_and_hash @definition_origin, @field, @parameter_index, @semantic_type
    end
    class UninitializedClassVar < DiagnosticBoundProducer
      getter declaration_origin : DiagnosticOrigin
      getter owner_type : String
      getter variable_name : String
      getter semantic_type : String
      def initialize(@declaration_origin : DiagnosticOrigin, @owner_type : String, @variable_name : String, @semantic_type : String); end
      def_equals_and_hash @declaration_origin, @owner_type, @variable_name, @semantic_type
    end
    class ConstantAccessor < DiagnosticBoundProducer
      getter definition_origin : DiagnosticOrigin
      getter prefix : String
      getter constant_name : String
      getter part : String
      def initialize(@definition_origin : DiagnosticOrigin, @prefix : String, @constant_name : String, @part : String); end
      def_equals_and_hash @definition_origin, @prefix, @constant_name, @part
    end
  end

  abstract class DiagnosticNameValue
    abstract def rendered_text : String
    abstract def artifact_origin : DiagnosticOrigin
    abstract def producer_context : String
    abstract def graph_bytes : UInt64
    abstract def to_json(json : JSON::Builder) : Nil

    class Observed < DiagnosticNameValue
      getter source_token : DiagnosticSourceNameToken
      def initialize(@source_token : DiagnosticSourceNameToken); end
      def rendered_text : String; @source_token.raw_text; end
      def artifact_origin : DiagnosticOrigin; @source_token.lexical_origin; end
      def producer_context : String; @source_token.context; end
      def graph_bytes : UInt64; 64_u64 + @source_token.graph_bytes; end
      def_equals_and_hash @source_token
      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Observed"
          json.field "source_token", @source_token
        end
      end
    end

    class Derived < DiagnosticNameValue
      getter origin : DiagnosticOrigin::DerivedName
      def initialize(@origin : DiagnosticOrigin::DerivedName); end
      def rendered_text : String; @origin.rendered_text; end
      def artifact_origin : DiagnosticOrigin; @origin; end
      def producer_context : String; @origin.producer_context; end
      def graph_bytes : UInt64; 64_u64 + @origin.graph_bytes; end
      def_equals_and_hash @origin
      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Derived"
          json.field "origin", @origin
        end
      end
    end
  end

  module DiagnosticNameMetadata
    def self.copy_and_validate(slots : Hash(DiagnosticNameSlot, Array(DiagnosticNameValue)), origin : DiagnosticOrigin? = nil)
      if slots.has_key?(DiagnosticNameSlot.new(DiagnosticNameSlotKind::EnumMember)) &&
         slots.has_key?(DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary))
        raise ArgumentError.new("conflicting enum member and parameter names")
      end
      remaining = DiagnosticOrigin::MAX_UNFOLDED_BYTES
      if origin
        raise ArgumentError.new("diagnostic name metadata exceeds size limit") if origin.graph_bytes > remaining
        remaining -= origin.graph_bytes
      end
      copy = {} of DiagnosticNameSlot => Array(DiagnosticNameValue)
      slots.each do |slot, tokens|
        raise ArgumentError.new("empty diagnostic name slot") if tokens.empty?
        if slot.kind.enum_member? && (tokens.size != 1 || tokens.first.producer_context != "enum_member")
          raise ArgumentError.new("invalid enum member name slot")
        end
        tokens.each do |token|
          raise ArgumentError.new("diagnostic name metadata exceeds size limit") if token.graph_bytes > remaining
          remaining -= token.graph_bytes
        end
        copy[slot] = tokens.dup
      end
      copy
    end
  end

  abstract class DiagnosticEmissionPart
    getter start_offset : Int32
    getter end_offset : Int32
    getter emitter_origin : DiagnosticOrigin?

    def initialize(@start_offset : Int32, @end_offset : Int32, @emitter_origin : DiagnosticOrigin?)
      raise ArgumentError.new("invalid macro emission extent") unless @start_offset >= 0 && @end_offset > @start_offset
      if emitter = @emitter_origin
        unless emitter.valid_for_anchor?("MacroDirective", "expression") || emitter.valid_for_anchor?("MacroDirective", "control")
          raise ArgumentError.new("invalid macro emission directive")
        end
      end
    end

    def to_json(json : JSON::Builder) : Nil
      json.object do
        case self
        when Generated then json.field "kind", "Generated"
        when AstAnchor then json.field "kind", "AstAnchor"
        when NameSplice then json.field "kind", "NameSplice"
        end
        json.field "start_offset", @start_offset
        json.field "end_offset", @end_offset
        json.field "emitter_origin", @emitter_origin
        case self
        when Generated
          json.field "producer", self.producer.to_s
        when AstAnchor
          json.field "source_origin", self.source_origin
        when NameSplice
          json.field "source_name", self.source_name
        end
      end
    end

    class Generated < DiagnosticEmissionPart
      getter producer : DiagnosticMacroProducer
      def initialize(start_offset : Int32, end_offset : Int32, emitter_origin : DiagnosticOrigin?, @producer : DiagnosticMacroProducer)
        super(start_offset, end_offset, emitter_origin)
      end
      def_equals_and_hash @start_offset, @end_offset, @emitter_origin, @producer
    end

    class AstAnchor < DiagnosticEmissionPart
      getter source_origin : DiagnosticOrigin
      def initialize(start_offset : Int32, end_offset : Int32, emitter_origin : DiagnosticOrigin?, @source_origin : DiagnosticOrigin)
        super(start_offset, end_offset, emitter_origin)
      end
      def_equals_and_hash @start_offset, @end_offset, @emitter_origin, @source_origin
    end

    class NameSplice < DiagnosticEmissionPart
      getter source_name : DiagnosticNameValue
      def initialize(start_offset : Int32, end_offset : Int32, emitter_origin : DiagnosticOrigin?,
                     @source_name : DiagnosticNameValue)
        super(start_offset, end_offset, emitter_origin)
        unless @end_offset - @start_offset == @source_name.rendered_text.bytesize
          raise ArgumentError.new("invalid diagnostic name splice extent")
        end
      end
      def_equals_and_hash @start_offset, @end_offset, @emitter_origin, @source_name
    end
  end

  enum DiagnosticMacroProducer
    ConstructedAst
    EmptyTupleProjection
    EmptyNamedTupleProjection
    MacroTemplate
    MacroId
    MacroVar
    MacroVerbatim
    YieldWrapper
    SemanticPrinter
    StructuredSyntax
    ArtifactSemanticRenderer
  end

  enum DiagnosticTokenSelection : UInt8
    Whole = 0
    SignedNumberSign = 1
  end
  enum DiagnosticWitnessRole : UInt8
    Open = 1
    Colon = 2
    Equals = 3
    Comma = 4
    Splat = 5
  end
  enum DiagnosticHeadSyntax : UInt8
    GlobalPathPrefix = 1
    FirstSplat = 2
    FirstUnderscore = 3
    ParenthesizedFirstTarget = 4
  end
  enum DiagnosticHeadRule : UInt8
    NamedArrayHead = 1
    NamedHashHead = 2
    ConstantAssignHead = 3
    ConstantTypeHead = 4
    MultiAssignHead = 5
  end
  enum DiagnosticPayloadRule : UInt8
    RegexInterpolationPayload = 1
    CommandInterpolationPayload = 2
  end

  abstract class DiagnosticFragmentHead
    class Anchor < DiagnosticFragmentHead
      getter anchor_index : Int32
      def initialize(@anchor_index : Int32)
        raise ArgumentError.new("negative fragment anchor reference") if @anchor_index < 0
      end
      def_equals_and_hash @anchor_index
    end
    class Syntax < DiagnosticFragmentHead
      getter form : DiagnosticHeadSyntax
      getter adjacent_anchor_index : Int32?
      def initialize(@form : DiagnosticHeadSyntax, @adjacent_anchor_index : Int32?)
        unless (@form == DiagnosticHeadSyntax::GlobalPathPrefix) == !@adjacent_anchor_index.nil?
          raise ArgumentError.new("invalid fragment head adjacency")
        end
        raise ArgumentError.new("negative fragment anchor reference") if @adjacent_anchor_index.try(&.<(0))
      end
      def_equals_and_hash @form, @adjacent_anchor_index
    end
  end

  abstract class DiagnosticFragmentAttachment
    class Direct < DiagnosticFragmentAttachment
      def_equals_and_hash
    end
    class HeadOf < DiagnosticFragmentAttachment
      getter rule : DiagnosticHeadRule
      getter head : DiagnosticFragmentHead
      def initialize(@rule : DiagnosticHeadRule, @head : DiagnosticFragmentHead); end
      def_equals_and_hash @rule, @head
    end
    class PayloadOf < DiagnosticFragmentAttachment
      getter rule : DiagnosticPayloadRule
      getter owner_anchor_index : Int32
      def initialize(@rule : DiagnosticPayloadRule, @owner_anchor_index : Int32)
        raise ArgumentError.new("negative fragment owner reference") if @owner_anchor_index < 0
      end
      def_equals_and_hash @rule, @owner_anchor_index
    end
  end

  class DiagnosticTokenEvent
    getter input_start : Int32
    getter input_end : Int32
    getter token_kind : String
    getter token_text : String
    getter lexical_mode : String
    getter selection : DiagnosticTokenSelection
    getter graph_bytes : UInt64
    getter graph_depth : Int32
    @byte_parts : Array(DiagnosticEmissionPart)

    def initialize(@input_start : Int32, @input_end : Int32, @token_kind : String, @token_text : String,
                   @lexical_mode : String, @selection : DiagnosticTokenSelection, byte_parts : Array(DiagnosticEmissionPart))
      unless @input_start >= 0 && @input_end > @input_start && @token_text.valid_encoding? &&
             @token_text.bytesize == @input_end - @input_start && !@token_kind.empty? &&
             {"Crystal", "Iyi"}.includes?(@lexical_mode) && {@selection.whole?, @selection.signed_number_sign?}.any?
        raise ArgumentError.new("invalid diagnostic token event")
      end
      if @selection.signed_number_sign?
        unless @token_kind == "NUMBER" && (@token_text.starts_with?("+") || @token_text.starts_with?("-")) &&
               @token_text.bytesize > 1 && (48_u8..57_u8).includes?(@token_text.byte_at(1))
          raise ArgumentError.new("invalid signed-number token selection")
        end
      end
      @byte_parts = byte_parts.dup
      raise ArgumentError.new("missing diagnostic token byte parts") if @byte_parts.empty?
      cursor = selected_start
      own = 1024_u64 + @token_text.bytesize.to_u64 * 6
      parents = [] of DiagnosticOrigin
      @byte_parts.each do |part|
        unless part.start_offset == cursor && part.end_offset <= selected_end
          raise ArgumentError.new("invalid diagnostic token byte coverage")
        end
        cursor = part.end_offset
        bytes = @token_text.byte_slice(part.start_offset - @input_start, part.end_offset - part.start_offset)
        raise ArgumentError.new("token event splits UTF-8") unless bytes.valid_encoding?
        part.emitter_origin.try { |origin| parents << origin }
        case part
        when DiagnosticEmissionPart::AstAnchor
          parents << part.source_origin
        when DiagnosticEmissionPart::NameSplice
          raise ArgumentError.new("name splice differs from output bytes") unless bytes == part.source_name.rendered_text
          case name = part.source_name
          when DiagnosticNameValue::Observed
            parents << name.source_token.lexical_origin
            name.source_token.binding_origin.try { |binding| parents << binding }
            own += name.source_token.raw_text.bytesize.to_u64 * 6 + 1024_u64
          when DiagnosticNameValue::Derived
            parents << name.origin
          end
        end
        own += 1024_u64
        raise ArgumentError.new("diagnostic token event exceeds size limit") if own > DiagnosticOrigin::MAX_UNFOLDED_BYTES
      end
      raise ArgumentError.new("incomplete diagnostic token byte coverage") unless cursor == selected_end
      depth = 0
      parents.each do |parent|
        raise ArgumentError.new("diagnostic token event exceeds depth limit") if parent.graph_depth + 1 > DiagnosticOrigin::MAX_DEPTH
        raise ArgumentError.new("diagnostic token event exceeds size limit") if parent.graph_bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES - own
        own += parent.graph_bytes
        depth = Math.max(depth, parent.graph_depth + 1)
      end
      @graph_bytes = own
      @graph_depth = depth
    end

    def selected_start : Int32; @input_start; end
    def selected_end : Int32; @selection.whole? ? @input_end : @input_start + 1; end
    def start_offset : Int32; selected_start; end
    def end_offset : Int32; selected_end; end
    def selected_text : String; @token_text.byte_slice(0, selected_end - selected_start); end
    def byte_parts : Array(DiagnosticEmissionPart); @byte_parts.dup; end
    def_equals_and_hash @input_start, @input_end, @token_kind, @token_text, @lexical_mode, @selection, @byte_parts

    def to_json(json : JSON::Builder) : Nil
      json.object do
        json.field "input_start", @input_start
        json.field "input_end", @input_end
        json.field "token_kind", @token_kind
        json.field "token_text", @token_text
        json.field "lexical_mode", @lexical_mode
        json.field "selection", @selection.to_s
        json.field "byte_parts" do
          json.array { @byte_parts.each { |part| part.to_json(json) } }
        end
      end
    end
  end

  record DiagnosticSyntaxWitness, role : DiagnosticWitnessRole, event : DiagnosticTokenEvent do
    def to_json(json : JSON::Builder) : Nil
      json.object do
        json.field "role", role.to_s
        json.field "event", event
      end
    end
  end

  abstract class DiagnosticAnchorEvidence
    def to_json(json : JSON::Builder) : Nil
      json.object do
        case self
        when Spliced
          json.field "kind", "Spliced"
          json.field "source_origin", self.source_origin
        when Constructed
          json.field "kind", "Constructed"
          json.field "producer", self.producer.to_s
        when RawSyntax
          json.field "kind", "RawSyntax"
          json.field "witnesses" do
            json.array { self.witnesses.each { |witness| witness.to_json(json) } }
          end
        when DerivedFromOwner
          json.field "kind", "DerivedFromOwner"
        end
      end
    end
    class Spliced < DiagnosticAnchorEvidence
      getter source_origin : DiagnosticOrigin
      def initialize(@source_origin : DiagnosticOrigin); end
      def_equals_and_hash @source_origin
    end
    class Constructed < DiagnosticAnchorEvidence
      getter producer : DiagnosticMacroProducer
      def initialize(@producer : DiagnosticMacroProducer)
        unless {DiagnosticMacroProducer::ConstructedAst, DiagnosticMacroProducer::EmptyTupleProjection,
                DiagnosticMacroProducer::EmptyNamedTupleProjection}.includes?(@producer)
          raise ArgumentError.new("invalid constructed anchor producer")
        end
      end
      def_equals_and_hash @producer
    end
    class RawSyntax < DiagnosticAnchorEvidence
      @witnesses : Array(DiagnosticSyntaxWitness)
      def initialize(witnesses : Array(DiagnosticSyntaxWitness)); @witnesses = witnesses.dup; end
      def witnesses : Array(DiagnosticSyntaxWitness); @witnesses.dup; end
      def_equals_and_hash @witnesses
    end
    class DerivedFromOwner < DiagnosticAnchorEvidence
      def_equals_and_hash
    end
  end

  abstract class DiagnosticHead
    def to_json(json : JSON::Builder) : Nil
      json.object do
        case self
        when Anchor
          json.field "kind", "Anchor"
          json.field "origin", self.origin
        when Syntax
          json.field "kind", "Syntax"
          json.field "form", self.form.to_s
          json.field "adjacent_name_origin", self.adjacent_name_origin
        end
      end
    end
    class Anchor < DiagnosticHead
      getter origin : DiagnosticOrigin::Expanded
      def initialize(@origin : DiagnosticOrigin::Expanded); end
      def_equals_and_hash @origin
    end
    class Syntax < DiagnosticHead
      getter form : DiagnosticHeadSyntax
      getter adjacent_name_origin : DiagnosticOrigin::Expanded?
      def initialize(@form : DiagnosticHeadSyntax, @adjacent_name_origin : DiagnosticOrigin::Expanded?)
        unless (@form == DiagnosticHeadSyntax::GlobalPathPrefix) == !@adjacent_name_origin.nil?
          raise ArgumentError.new("invalid syntax head adjacency")
        end
      end
      def_equals_and_hash @form, @adjacent_name_origin
    end
  end

  abstract class DiagnosticAnchorUse
    def to_json(json : JSON::Builder) : Nil
      json.object do
        case self
        when Direct
          json.field "kind", "Direct"
        when HeadOf
          json.field "kind", "HeadOf"
          json.field "rule", self.rule.to_s
          json.field "evidence", self.evidence
          json.field "head", self.head
          json.field "emitter_origin", self.emitter_origin
        when PayloadOf
          json.field "kind", "PayloadOf"
          json.field "rule", self.rule.to_s
          json.field "evidence", self.evidence
          json.field "owner_origin", self.owner_origin
          json.field "emitter_origin", self.emitter_origin
        end
      end
    end
    class Direct < DiagnosticAnchorUse
      def_equals_and_hash
    end
    class HeadOf < DiagnosticAnchorUse
      getter rule : DiagnosticHeadRule
      getter evidence : DiagnosticAnchorEvidence
      getter head : DiagnosticHead
      getter emitter_origin : DiagnosticOrigin?
      def initialize(@rule : DiagnosticHeadRule, @evidence : DiagnosticAnchorEvidence, @head : DiagnosticHead, @emitter_origin : DiagnosticOrigin?)
        raise ArgumentError.new("invalid head evidence") if @evidence.is_a?(DiagnosticAnchorEvidence::DerivedFromOwner)
        if (constructed = @evidence.as?(DiagnosticAnchorEvidence::Constructed)) && constructed.producer != DiagnosticMacroProducer::ConstructedAst
          raise ArgumentError.new("invalid head constructed producer")
        end
        DiagnosticAnchorUse.validate_emitter(@emitter_origin, @evidence)
      end
      def_equals_and_hash @rule, @evidence, @head, @emitter_origin
    end
    class PayloadOf < DiagnosticAnchorUse
      getter rule : DiagnosticPayloadRule
      getter evidence : DiagnosticAnchorEvidence
      getter owner_origin : DiagnosticOrigin::Expanded
      getter emitter_origin : DiagnosticOrigin?
      def initialize(@rule : DiagnosticPayloadRule, @evidence : DiagnosticAnchorEvidence, @owner_origin : DiagnosticOrigin::Expanded, @emitter_origin : DiagnosticOrigin?)
        raise ArgumentError.new("invalid payload evidence") if @evidence.is_a?(DiagnosticAnchorEvidence::RawSyntax)
        if (constructed = @evidence.as?(DiagnosticAnchorEvidence::Constructed)) && constructed.producer != DiagnosticMacroProducer::ConstructedAst
          raise ArgumentError.new("invalid payload constructed producer")
        end
        DiagnosticAnchorUse.validate_emitter(@emitter_origin, @evidence)
      end
      def_equals_and_hash @rule, @evidence, @owner_origin, @emitter_origin
    end

    def self.validate_emitter(emitter : DiagnosticOrigin?, evidence : DiagnosticAnchorEvidence) : Nil
      if emitter
        unless emitter.valid_for_anchor?("MacroDirective", "expression") || emitter.valid_for_anchor?("MacroDirective", "control")
          raise ArgumentError.new("invalid attachment emitter")
        end
      end
      if (evidence.is_a?(DiagnosticAnchorEvidence::RawSyntax) || evidence.is_a?(DiagnosticAnchorEvidence::DerivedFromOwner)) && emitter
        raise ArgumentError.new("raw attachment must not have an emitter")
      end
    end
  end

  enum DiagnosticRenderedLexContext : UInt8
    Operand = 1
    Operator = 2
    DefOrMacroName = 3
    TypeName = 4
  end

  record DiagnosticRenderedToken, input_start : Int32, input_end : Int32,
    token_kind : String, token_text : String, lexical_mode : String

  module DiagnosticRenderedTokens
    def self.observe_one(input : String, start : Int32, finish : Int32, lexical_mode : String,
                         context : DiagnosticRenderedLexContext) : DiagnosticRenderedToken
      base = input.starts_with?('\uFEFF') ? 3 : 0
      unless input.valid_encoding? && start >= base && finish > start && finish <= input.bytesize &&
             {"Crystal", "Iyi"}.includes?(lexical_mode)
        raise ArgumentError.new("invalid rendered token input")
      end
      lexer = Lexer.new(input)
      lexer.iyi = lexical_mode == "Iyi"
      lexer.current_pos = start - base
      lexer.slash_is_regex = context == DiagnosticRenderedLexContext::Operand
      lexer.wants_regex = context == DiagnosticRenderedLexContext::Operand
      lexer.wants_def_or_macro_name = context == DiagnosticRenderedLexContext::DefOrMacroName
      begin
        lexer.next_token
      rescue ex : SyntaxException
        raise DiagnosticDestinationSyntaxError.new(lexical_mode, ex.message || "lexer rejected destination syntax", start, finish)
      end
      token = lexer.token
      unless token.input_offset == start && token.input_end == finish
        raise DiagnosticDestinationSyntaxError.new(lexical_mode, "rendered token does not match measured writer extent", start, finish)
      end
      DiagnosticRenderedToken.new(start, finish, token.type.to_s, input.byte_slice(start, finish - start), lexical_mode)
    end
  end

  class DiagnosticFragmentBuilder
    @events = [] of DiagnosticTokenEvent
    @anchors = [] of DiagnosticAnchor
    getter lexical_mode : String

    def initialize(@lexical_mode : String)
      raise ArgumentError.new("invalid fragment lexical mode") unless {"Crystal", "Iyi"}.includes?(@lexical_mode)
    end

    def event_count : Int32; @events.size; end
    def anchor_count : Int32; @anchors.size; end
    def event_at(index : Int32) : DiagnosticTokenEvent; @events[index]; end
    def anchor_at(index : Int32) : DiagnosticAnchor; @anchors[index]; end

    def add_written_syntax(start_offset : Int32, end_offset : Int32, rendered : String,
                           context : DiagnosticRenderedLexContext, producer : DiagnosticMacroProducer) : Int32
      observed = DiagnosticRenderedTokens.observe_one(rendered, start_offset, end_offset, @lexical_mode, context)
      part = DiagnosticEmissionPart::Generated.new(start_offset, end_offset, nil, producer)
      event = DiagnosticTokenEvent.new(start_offset, end_offset, observed.token_kind, observed.token_text,
        @lexical_mode, DiagnosticTokenSelection::Whole, [part] of DiagnosticEmissionPart)
      add_event(event)
    end

    def add_event(event : DiagnosticTokenEvent) : Int32
      raise ArgumentError.new("fragment event lexical mode mismatch") unless event.lexical_mode == @lexical_mode
      @events.each_with_index do |existing, index|
        if existing.selected_start == event.selected_start && existing.selected_end == event.selected_end
          raise ArgumentError.new("conflicting fragment token events") unless existing == event
          return index
        end
        if existing.selected_start < event.selected_end && event.selected_start < existing.selected_end
          raise ArgumentError.new("overlapping fragment token events")
        end
      end
      @events << event
      @events.size - 1
    end

    def add_anchor(anchor : DiagnosticAnchor) : Int32
      unless anchor.event_index >= 0 && anchor.event_index < @events.size
        raise ArgumentError.new("fragment anchor references missing event")
      end
      if @anchors.any? { |item| item.offset == anchor.offset && item.kind == anchor.kind && item.role == anchor.role }
        raise ArgumentError.new("duplicate fragment anchor")
      end
      @anchors << anchor
      @anchors.size - 1
    end

    # Observe the complete output, since an isolated slice can change lexer state
    # or silently strip a BOM that was not at the beginning of the input.
    def add_written_anchor(start_offset : Int32, end_offset : Int32, rendered : String, context : DiagnosticRenderedLexContext,
                           kind : String, role : String, origin : DiagnosticOrigin,
                           name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticNameValue))) : Int32
      raise ArgumentError.new("invalid measured fragment origin") unless origin.valid_for_anchor?(kind, role)
      observed = DiagnosticRenderedTokens.observe_one(rendered, start_offset, end_offset, @lexical_mode, context)
      bytes = observed.token_text
      part = if name_slots.empty?
               DiagnosticEmissionPart::AstAnchor.new(start_offset, end_offset, nil, origin).as(DiagnosticEmissionPart)
             else
               raise ArgumentError.new("fragment name anchor has multiple slots") unless name_slots.size == 1
               names = name_slots.values.first
               raise ArgumentError.new("fragment name anchor has multiple values") unless names.size == 1
               name = names.first
               unless name.rendered_text == bytes && name.artifact_origin == origin
                 raise ArgumentError.new("fragment name differs from measured bytes")
               end
               DiagnosticEmissionPart::NameSplice.new(start_offset, end_offset, nil, name).as(DiagnosticEmissionPart)
             end
      event = DiagnosticTokenEvent.new(start_offset, end_offset, observed.token_kind, bytes, @lexical_mode,
        DiagnosticTokenSelection::Whole, [part] of DiagnosticEmissionPart)
      event_index = add_event(event)
      add_anchor(DiagnosticAnchor.new(start_offset, kind, role, origin, name_slots,
        event_index, DiagnosticFragmentAttachment::Direct.new))
    end

    def canonicalize : {Array(DiagnosticTokenEvent), Array(DiagnosticAnchor)}
      events_with_index = @events.each_with_index.to_a
      events_with_index.sort_by! do |event, _|
        {event.selected_start, event.selected_end, event.selection.value, event.token_kind, event.token_text, event.lexical_mode}
      end
      event_remap = Array(Int32).new(@events.size, 0)
      events = events_with_index.map_with_index do |(event, old_index), new_index|
        event_remap[old_index] = new_index
        event
      end

      remaining = (0...@anchors.size).to_a
      anchor_remap = {} of Int32 => Int32
      anchors = [] of DiagnosticAnchor
      until remaining.empty?
        ready = remaining.select do |index|
          attachment = @anchors[index].attachment
          dependency = case attachment
                       when DiagnosticFragmentAttachment::HeadOf
                         case head = attachment.head
                         when DiagnosticFragmentHead::Anchor then head.anchor_index
                         when DiagnosticFragmentHead::Syntax then head.adjacent_anchor_index
                         end
                       when DiagnosticFragmentAttachment::PayloadOf then attachment.owner_anchor_index
                       end
          dependency.nil? || anchor_remap.has_key?(dependency)
        end
        raise ArgumentError.new("cyclic or missing fragment anchor dependency") if ready.empty?
        index = ready.min_by { |item| anchor = @anchors[item]; {anchor.offset, anchor.kind, anchor.role} }
        original = @anchors[index]
        attachment = case part = original.attachment
                     when DiagnosticFragmentAttachment::Direct
                       DiagnosticFragmentAttachment::Direct.new.as(DiagnosticFragmentAttachment)
                     when DiagnosticFragmentAttachment::HeadOf
                       head = case old = part.head
                              when DiagnosticFragmentHead::Anchor
                                DiagnosticFragmentHead::Anchor.new(anchor_remap[old.anchor_index]).as(DiagnosticFragmentHead)
                              when DiagnosticFragmentHead::Syntax
                                adjacent = old.adjacent_anchor_index.try { |item| anchor_remap[item] }
                                DiagnosticFragmentHead::Syntax.new(old.form, adjacent).as(DiagnosticFragmentHead)
                              else
                                raise ArgumentError.new("unknown fragment head")
                              end
                       DiagnosticFragmentAttachment::HeadOf.new(part.rule, head).as(DiagnosticFragmentAttachment)
                     when DiagnosticFragmentAttachment::PayloadOf
                       DiagnosticFragmentAttachment::PayloadOf.new(part.rule, anchor_remap[part.owner_anchor_index]).as(DiagnosticFragmentAttachment)
                     else
                       raise ArgumentError.new("unknown fragment attachment")
                     end
        anchor_remap[index] = anchors.size
        anchors << original.copy_with(event_index: event_remap[original.event_index], attachment: attachment)
        remaining.delete(index)
      end
      {events, anchors}
    end

    def finish_data(text : String) : DiagnosticFragmentData
      events, anchors = canonicalize
      DiagnosticFragmentData.new(text, events, anchors)
    end

    def finish(key : String, text : String) : IyiMod::DiagnosticFragment
      finish_data(text).to_fragment(key)
    end
  end

  module DiagnosticFragmentValidation
    def self.canonicalize(events : Array(DiagnosticTokenEvent), anchors : Array(DiagnosticAnchor)) : {Array(DiagnosticTokenEvent), Array(DiagnosticAnchor)}
      if events.empty?
        raise ArgumentError.new("anchors without fragment events") unless anchors.empty?
        return {[] of DiagnosticTokenEvent, [] of DiagnosticAnchor}
      end
      builder = DiagnosticFragmentBuilder.new(events.first.lexical_mode)
      events.each_with_index do |event, index|
        raise ArgumentError.new("duplicate fragment token event") unless builder.add_event(event) == index
      end
      anchors.each { |anchor| builder.add_anchor(anchor) }
      builder.canonicalize
    end

    def self.validate_canonical!(events : Array(DiagnosticTokenEvent), anchors : Array(DiagnosticAnchor)) : Nil
      ordered_events, ordered_anchors = canonicalize(events, anchors)
      unless ordered_events == events && ordered_anchors == anchors
        raise ArgumentError.new("noncanonical fragment diagnostics")
      end
      used = Set(Int32).new
      direct = Set(Int32).new
      anchors.each_with_index do |anchor, index|
        event = events[anchor.event_index]? || raise ArgumentError.new("missing fragment event")
        raise ArgumentError.new("fragment anchor offset mismatch") unless anchor.offset == event.selected_start
        raise ArgumentError.new("fragment anchor lacks matching origin") unless anchor.origin.try(&.valid_for_anchor?(anchor.kind, anchor.role))
        used << anchor.event_index
        case attachment = anchor.attachment
        when DiagnosticFragmentAttachment::Direct
          raise ArgumentError.new("duplicate direct fragment writer") unless direct.add?(anchor.event_index)
        when DiagnosticFragmentAttachment::HeadOf
          expected = case attachment.rule
                     when DiagnosticHeadRule::NamedArrayHead then {"Literal", "array"}
                     when DiagnosticHeadRule::NamedHashHead then {"Literal", "hash"}
                     when DiagnosticHeadRule::ConstantAssignHead, DiagnosticHeadRule::ConstantTypeHead then {"Assign", "constant"}
                     when DiagnosticHeadRule::MultiAssignHead then {"Literal", "multiassign"}
                     else raise ArgumentError.new("unknown fragment head rule")
                     end
          raise ArgumentError.new("fragment head role mismatch") unless {anchor.kind, anchor.role} == expected
          case head = attachment.head
          when DiagnosticFragmentHead::Anchor
            child = anchors[head.anchor_index]? || raise ArgumentError.new("missing fragment head")
            unless head.anchor_index < index && child.event_index == anchor.event_index
              raise ArgumentError.new("fragment head event mismatch")
            end
            allowed = if attachment.rule == DiagnosticHeadRule::MultiAssignHead
                        (child.kind == "Name" && {"path_segment", "local_reference", "instance_variable", "class_variable", "special_global"}.includes?(child.role)) ||
                          (child.kind == "Call" && child.role == "method") ||
                          (child.kind == "Literal" && {"array", "hash", "regex", "interpolation", "range", "case", "select"}.includes?(child.role)) ||
                          ({"ProcLiteral", "ProcPointer"}.includes?(child.kind) && child.role == "arrow") ||
                          (child.kind == "Cast" && child.role == "keyword")
                      else
                        child.kind == "Name" && child.role == "path_segment"
                      end
            unless allowed && child.attachment.is_a?(DiagnosticFragmentAttachment::Direct)
              raise ArgumentError.new("invalid fragment head child role")
            end
          when DiagnosticFragmentHead::Syntax
            text = case head.form
                   when DiagnosticHeadSyntax::GlobalPathPrefix then "::"
                   when DiagnosticHeadSyntax::FirstSplat then "*"
                   when DiagnosticHeadSyntax::FirstUnderscore then "_"
                   when DiagnosticHeadSyntax::ParenthesizedFirstTarget then "("
                   else raise ArgumentError.new("unknown fragment syntax head")
                   end
            unless event.selection.whole? && event.token_kind == text && event.token_text == text
              raise ArgumentError.new("fragment syntax head mismatch")
            end
            if adjacent_index = head.adjacent_anchor_index
              child = anchors[adjacent_index]? || raise ArgumentError.new("missing adjacent fragment name")
              child_event = events[child.event_index]
              unless adjacent_index < index && child.kind == "Name" && child.role == "path_segment" &&
                     child.attachment.is_a?(DiagnosticFragmentAttachment::Direct) && child_event.token_kind == "CONST" &&
                     child_event.lexical_mode == event.lexical_mode && child_event.selected_start == event.selected_end
                raise ArgumentError.new("invalid fragment head adjacency")
              end
            elsif head.form != DiagnosticHeadSyntax::GlobalPathPrefix && attachment.rule != DiagnosticHeadRule::MultiAssignHead
              raise ArgumentError.new("invalid punctuation head rule")
            end
          end
        when DiagnosticFragmentAttachment::PayloadOf
          owner = anchors[attachment.owner_anchor_index]? || raise ArgumentError.new("missing fragment payload owner")
          expected = attachment.rule == DiagnosticPayloadRule::RegexInterpolationPayload ? {"Literal", "regex"} : {"Call", "method"}
          unless attachment.owner_anchor_index < index && {anchor.kind, anchor.role} == {"Literal", "interpolation"} &&
                 {owner.kind, owner.role} == expected && owner.event_index == anchor.event_index &&
                 owner.attachment.is_a?(DiagnosticFragmentAttachment::Direct)
            raise ArgumentError.new("invalid fragment payload relationship")
          end
          openers = attachment.rule == DiagnosticPayloadRule::RegexInterpolationPayload ?
            {"/", "%r(", "%r<", "%r[", "%r{", "%r|"} : {"`", "%x(", "%x<", "%x[", "%x{", "%x|"}
          unless event.selection.whole? && event.token_kind == "DELIMITER_START" && openers.includes?(event.token_text)
            raise ArgumentError.new("invalid fragment payload opener")
          end
        else
          raise ArgumentError.new("unknown fragment attachment")
        end
      end
      raise ArgumentError.new("unconsumed fragment token event") unless used.size == events.size
    end

    def self.validate_text!(text : String, events : Array(DiagnosticTokenEvent), anchors : Array(DiagnosticAnchor)) : Nil
      raise ArgumentError.new("invalid fragment text") unless text.valid_encoding?
      validate_canonical!(events, anchors)
      events.each do |event|
        unless event.input_end <= text.bytesize &&
               text.byte_slice(event.input_start, event.input_end - event.input_start) == event.token_text
          raise ArgumentError.new("fragment token bytes do not match text")
        end
      end
    end
  end

  class DiagnosticDestinationSyntaxError < Exception
    getter lexical_mode : String
    getter detail : String
    getter start_offset : Int32?
    getter end_offset : Int32?
    def initialize(@lexical_mode : String, @detail : String, @start_offset : Int32? = nil, @end_offset : Int32? = nil)
      raise ArgumentError.new("invalid destination failure mode") unless {"Crystal", "Iyi"}.includes?(@lexical_mode)
      super("#{@lexical_mode}: #{@detail}")
    end
    def_equals_and_hash @lexical_mode, @detail, @start_offset, @end_offset
  end

  class DiagnosticFragmentData
    getter text_sha256 : String
    @events : Array(DiagnosticTokenEvent)
    @anchors : Array(DiagnosticAnchor)
    def initialize(text : String, events : Array(DiagnosticTokenEvent), anchors : Array(DiagnosticAnchor))
      DiagnosticFragmentValidation.validate_text!(text, events, anchors)
      @text_sha256 = ::Crystal::Digest::SHA256.hexdigest(text)
      @events = events.dup
      @anchors = anchors.dup
    end
    def events : Array(DiagnosticTokenEvent); @events.dup; end
    def anchors : Array(DiagnosticAnchor); @anchors.dup; end
    def to_fragment(key : String) : IyiMod::DiagnosticFragment
      IyiMod::DiagnosticFragment.new(key, @text_sha256, @events.dup, @anchors.dup)
    end
    def_equals_and_hash @text_sha256, @events, @anchors
  end

  abstract class DiagnosticModeCaptureResult
    class Success < DiagnosticModeCaptureResult
      getter data : DiagnosticFragmentData
      def initialize(@data : DiagnosticFragmentData); end
      def_equals_and_hash @data
    end
    class Failure < DiagnosticModeCaptureResult
      getter error : DiagnosticDestinationSyntaxError
      def initialize(@error : DiagnosticDestinationSyntaxError); end
      def_equals_and_hash @error
    end
  end

  class DiagnosticModeCaptures
    getter text : String
    getter crystal : DiagnosticModeCaptureResult
    getter iyi : DiagnosticModeCaptureResult
    @positions : Array(IyiMod::SourcePosition)

    def initialize(@text : String, positions : Array(IyiMod::SourcePosition), @crystal : DiagnosticModeCaptureResult,
                   @iyi : DiagnosticModeCaptureResult)
      @positions = positions.dup
      digest = ::Crystal::Digest::SHA256.hexdigest(@text)
      {"Crystal", "Iyi"}.zip({@crystal, @iyi}).each do |mode, outcome|
        case outcome
        when DiagnosticModeCaptureResult::Success
          unless outcome.data.text_sha256 == digest && outcome.data.events.all? { |event| event.lexical_mode == mode }
            raise ArgumentError.new("destination capture differs from authoritative text or mode")
          end
        when DiagnosticModeCaptureResult::Failure
          raise ArgumentError.new("destination failure mode mismatch") unless outcome.error.lexical_mode == mode
        else
          raise ArgumentError.new("invalid destination capture outcome")
        end
      end
    end

    def positions : Array(IyiMod::SourcePosition); @positions.dup; end

    def self.capture(text : String, positions : Array(IyiMod::SourcePosition),
                     &block : String -> {String, Array(IyiMod::SourcePosition), DiagnosticFragmentBuilder}) : DiagnosticModeCaptures
      results = ["Crystal", "Iyi"].map do |mode|
        begin
          rendered, actual_positions, builder = yield mode
          unless rendered == text && actual_positions == positions && builder.lexical_mode == mode
            raise ArgumentError.new("destination capture changed authoritative rendering")
          end
          DiagnosticModeCaptureResult::Success.new(builder.finish_data(rendered)).as(DiagnosticModeCaptureResult)
        rescue ex : DiagnosticDestinationSyntaxError
          raise ex unless ex.lexical_mode == mode
          DiagnosticModeCaptureResult::Failure.new(ex).as(DiagnosticModeCaptureResult)
        end
      end
      new(text, positions, results[0], results[1])
    end

    def data(mode : String) : DiagnosticFragmentData
      result = case mode
               when "Crystal" then @crystal
               when "Iyi" then @iyi
               else raise ArgumentError.new("invalid destination mode")
               end
      case result
      when DiagnosticModeCaptureResult::Success then result.data
      when DiagnosticModeCaptureResult::Failure then raise result.error
      else raise ArgumentError.new("invalid destination capture outcome")
      end
    end
    def fragment(key : String, mode : String) : IyiMod::DiagnosticFragment
      data(mode).to_fragment(key)
    end
    def_equals_and_hash @text, @positions, @crystal, @iyi
  end

  record DiagnosticWriterRef, start_offset : Int32, end_offset : Int32
  record DiagnosticMacroClaimKey, writer : DiagnosticWriterRef, kind : String, role : String

  abstract class DiagnosticMacroHead
    class Anchor < DiagnosticMacroHead
      getter writer : DiagnosticWriterRef
      def initialize(@writer : DiagnosticWriterRef); end
      def_equals_and_hash @writer
    end
    class Syntax < DiagnosticMacroHead
      getter form : DiagnosticHeadSyntax
      getter writer : DiagnosticWriterRef
      getter adjacent_name_writer : DiagnosticWriterRef?
      def initialize(@form : DiagnosticHeadSyntax, @writer : DiagnosticWriterRef, @adjacent_name_writer : DiagnosticWriterRef?); end
      def_equals_and_hash @form, @writer, @adjacent_name_writer
    end
  end

  abstract class DiagnosticMacroAttachment
    class Direct < DiagnosticMacroAttachment
      getter writer : DiagnosticWriterRef
      def initialize(@writer : DiagnosticWriterRef); end
      def_equals_and_hash @writer
    end
    class HeadOf < DiagnosticMacroAttachment
      getter rule : DiagnosticHeadRule
      getter head : DiagnosticMacroHead
      def initialize(@rule : DiagnosticHeadRule, @head : DiagnosticMacroHead); end
      def_equals_and_hash @rule, @head
    end
    class PayloadOf < DiagnosticMacroAttachment
      getter rule : DiagnosticPayloadRule
      getter owner_key : DiagnosticMacroClaimKey
      def initialize(@rule : DiagnosticPayloadRule, @owner_key : DiagnosticMacroClaimKey); end
      def_equals_and_hash @rule, @owner_key
    end
  end

  record DiagnosticMacroClaim, key : DiagnosticMacroClaimKey, evidence : DiagnosticAnchorEvidence,
    attachment : DiagnosticMacroAttachment, emitter_origin : DiagnosticOrigin?


  record DiagnosticGeneratedText, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, producer : DiagnosticMacroProducer

  record DiagnosticMacroNameFragment, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, source_name : DiagnosticNameValue do
    def writer : DiagnosticWriterRef
      DiagnosticWriterRef.new(start_offset, end_offset)
    end
  end

  # Provenance is independent of Location, which remains the source of
  # human-facing positions. These records contain no process-local identity.
  abstract class DiagnosticOrigin
    abstract def to_json(json : JSON::Builder) : Nil
    abstract def valid_for_anchor?(kind : String, role : String) : Bool

    MAX_DEPTH          = 128
    MAX_UNFOLDED_BYTES = 8_u64 * 1024 * 1024
    getter graph_depth : Int32 = 0
    getter graph_bytes : UInt64 = 0_u64

    protected def set_graph_bounds!(own_bytes : UInt64, parents : Array(DiagnosticOrigin)) : Nil
      depth = 0
      total = own_bytes
      parents.each do |parent|
        depth = Math.max(depth, parent.graph_depth + 1)
        raise ArgumentError.new("diagnostic origin graph exceeds size limit") if parent.graph_bytes > MAX_UNFOLDED_BYTES - Math.min(total, MAX_UNFOLDED_BYTES)
        total += parent.graph_bytes
      end
      raise ArgumentError.new("diagnostic origin graph exceeds depth limit") if depth > MAX_DEPTH
      raise ArgumentError.new("diagnostic origin graph exceeds size limit") if total > MAX_UNFOLDED_BYTES
      @graph_depth = depth
      @graph_bytes = total
    end

    def self.json_string_size(text : String) : UInt64
      size = 2_u64
      text.each_byte do |byte|
        size += case byte
                when 0x22, 0x5c, 0x08, 0x0c, 0x0a, 0x0d, 0x09 then 2_u64
                when 0x00..0x1f, 0x7f                         then 6_u64
                else                                               1_u64
                end
      end
      size
    end

    def valid_for_binding? : Bool
      false
    end

    def as_json : JSON::Any
      JSON.parse(to_json)
    end

    # Only codegen may select this identity, after establishing that the
    # physical semantic scope is Program rather than an omitted typed def.
    def program_specialization_json : JSON::Any
      root = case self
             when Written   then self
             when Expanded  then self.invocation_origin.written_invocation_root
             when Synthetic then self.parent_origin.written_invocation_root
             else                raise ArgumentError.new("unknown diagnostic origin")
             end
      JSON.parse(JSON.build do |json|
        json.object do
          json.field "kind", "program_scope"
          json.field "source_identity" do
            json.object do
              json.field "module", root.source_module
              json.field "file", root.source_file
            end
          end
        end
      end)
    end

    def written_invocation_root : Written
      case self
      when Written   then self
      when Expanded  then self.invocation_origin.written_invocation_root
      when Synthetic then self.parent_origin.written_invocation_root
      else                raise ArgumentError.new("unknown diagnostic origin")
      end
    end

    def self.require_text(value : String, field : String) : String
      raise ArgumentError.new("empty diagnostic origin #{field}") if value.empty?
      raise ArgumentError.new("invalid UTF-8 in diagnostic origin #{field}") unless value.valid_encoding?
      value
    end

    def self.require_offset(value : Int32, field : String) : Int32
      raise ArgumentError.new("negative diagnostic origin #{field}") if value < 0
      value
    end

    class DecodeBudget
      @used = 0_u64

      def consume(bytes : UInt64) : Nil
        raise ArgumentError.new("diagnostic origin graph exceeds size limit") if bytes > MAX_UNFOLDED_BYTES - @used
        @used += bytes
      end

      def text(value : String) : Nil
        consume(DiagnosticOrigin.json_string_size(value))
      end
    end

    # The artifact reader must reject a partial or extended record rather than
    # treating it as an equivalent origin.
    def self.from_json(value : JSON::Any, depth : Int32 = 0, budget : DecodeBudget = DecodeBudget.new) : DiagnosticOrigin
      raise ArgumentError.new("diagnostic origin nesting is too deep") if depth > 128
      budget.consume(1_u64)
      object = value.as_h
      kind = object["kind"].as_s
      case kind
      when "Written"
        expected_keys(object, %w(kind source_identity input_byte_offset anchor_kind role))
        source = object["source_identity"].as_h
        expected_keys(source, %w(module file))
        budget.text(source["module"].as_s)
        budget.text(source["file"].as_s)
        budget.text(object["anchor_kind"].as_s)
        budget.text(object["role"].as_s)
        Written.new(source["module"].as_s, source["file"].as_s,
          object["input_byte_offset"].as_i, object["anchor_kind"].as_s, object["role"].as_s)
      when "Expanded"
        expected_keys(object, %w(kind invocation_origin macro_definition_origin expansion_guard anchor_kind role name_context token_event anchor_use))
        %w(expansion_guard anchor_kind role).each { |key| budget.text(object[key].as_s) }
        budget.text(object["name_context"].as_s) unless object["name_context"].raw.nil?
        Expanded.new(from_json(object["invocation_origin"], depth + 1, budget),
          from_json(object["macro_definition_origin"], depth + 1, budget), object["expansion_guard"].as_s,
          object["anchor_kind"].as_s, object["role"].as_s, object["name_context"].as_s?,
          token_event_from_json(object["token_event"], depth + 1, budget),
          anchor_use_from_json(object["anchor_use"], depth + 1, budget))
      when "DerivedName"
        case object["derivation_kind"].as_s
        when "ParameterLowering"
          expected_keys(object, %w(kind derivation_kind source_token definition_origin parameter_slot parameter_index result projection fresh_index))
          %w(parameter_slot result projection).each { |key| budget.text(object[key].as_s) }
          DerivedName.new(source_token_from_json(object["source_token"], depth + 1, budget),
            from_json(object["definition_origin"], depth + 1, budget), object["parameter_slot"].as_s,
            object["parameter_index"].as_i, object["result"].as_s, object["projection"].as_s,
            object["fresh_index"].raw.nil? ? nil : object["fresh_index"].as_i)
        when "RegexMatchIndex"
          expected_keys(object, %w(kind derivation_kind source_token result))
          budget.text(object["result"].as_s)
          DerivedName.regex_match_index(source_token_from_json(object["source_token"], depth + 1, budget), object["result"].as_s)
        when "TypeSugar"
          expected_keys(object, %w(kind derivation_kind production witnesses result lowering_index))
          budget.consume(object["witnesses"].as_a.size.to_u64 * 512_u64)
          witnesses = object["witnesses"].as_a.map do |value|
            token = value.as_h
            expected_keys(token, %w(lexical_origin input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
            %w(input_sha256 lexical_mode token_kind raw_text).each { |key| budget.text(token[key].as_s) }
            DiagnosticSourceSyntaxToken.new(from_json(token["lexical_origin"], depth + 1, budget),
              token["input_sha256"].as_s, token["input_bytesize"].as_i, token["input_start"].as_i,
              token["input_end"].as_i, token["lexical_mode"].as_s, token["token_kind"].as_s, token["raw_text"].as_s)
          end
          DerivedName.type_sugar(DiagnosticTypeSugar.parse(object["production"].as_s), witnesses,
            DiagnosticTypeSugarResult.parse(object["result"].as_s), object["lowering_index"].as_i)
        else
          raise ArgumentError.new("unknown diagnostic name derivation")
        end
      when "Synthetic"
        expected_keys(object, %w(kind parent_origin synthesis_kind structural_slot))
        budget.text(object["synthesis_kind"].as_s)
        budget.text(object["structural_slot"].as_s)
        Synthetic.new(from_json(object["parent_origin"], depth + 1, budget),
          object["synthesis_kind"].as_s, object["structural_slot"].as_s)
      else
        raise ArgumentError.new("unknown diagnostic origin kind #{kind}")
      end
    end

    private def self.token_event_from_json(value : JSON::Any, depth : Int32, budget : DecodeBudget) : DiagnosticTokenEvent
      event = value.as_h
      expected_keys(event, %w(input_start input_end token_kind token_text lexical_mode selection byte_parts))
      %w(token_kind token_text lexical_mode selection).each { |key| budget.text(event[key].as_s) }
      budget.consume(event["byte_parts"].as_a.size.to_u64 * 1024_u64)
      parts = event["byte_parts"].as_a.map do |part|
        fields = part.as_h
        emitter = fields["emitter_origin"]
        emitter_origin = emitter.raw.nil? ? nil : from_json(emitter, depth + 1, budget)
        start = fields["start_offset"].as_i
        finish = fields["end_offset"].as_i
        case fields["kind"].as_s
        when "Generated"
          expected_keys(fields, %w(kind start_offset end_offset emitter_origin producer))
          DiagnosticEmissionPart::Generated.new(start, finish, emitter_origin, DiagnosticMacroProducer.parse(fields["producer"].as_s)).as(DiagnosticEmissionPart)
        when "AstAnchor"
          expected_keys(fields, %w(kind start_offset end_offset emitter_origin source_origin))
          DiagnosticEmissionPart::AstAnchor.new(start, finish, emitter_origin, from_json(fields["source_origin"], depth + 1, budget)).as(DiagnosticEmissionPart)
        when "NameSplice"
          expected_keys(fields, %w(kind start_offset end_offset emitter_origin source_name))
          DiagnosticEmissionPart::NameSplice.new(start, finish, emitter_origin, name_value_from_json(fields["source_name"], depth + 1, budget)).as(DiagnosticEmissionPart)
        else
          raise ArgumentError.new("unknown diagnostic emission part")
        end
      end
      DiagnosticTokenEvent.new(event["input_start"].as_i, event["input_end"].as_i, event["token_kind"].as_s,
        event["token_text"].as_s, event["lexical_mode"].as_s, DiagnosticTokenSelection.parse(event["selection"].as_s), parts)
    end

    private def self.anchor_evidence_from_json(value : JSON::Any, depth : Int32, budget : DecodeBudget) : DiagnosticAnchorEvidence
      fields = value.as_h
      case fields["kind"].as_s
      when "Spliced"
        expected_keys(fields, %w(kind source_origin))
        DiagnosticAnchorEvidence::Spliced.new(from_json(fields["source_origin"], depth + 1, budget))
      when "Constructed"
        expected_keys(fields, %w(kind producer))
        DiagnosticAnchorEvidence::Constructed.new(DiagnosticMacroProducer.parse(fields["producer"].as_s))
      when "RawSyntax"
        expected_keys(fields, %w(kind witnesses))
        budget.consume(fields["witnesses"].as_a.size.to_u64 * 512_u64)
        witnesses = fields["witnesses"].as_a.map do |item|
          witness = item.as_h
          expected_keys(witness, %w(role event))
          DiagnosticSyntaxWitness.new(DiagnosticWitnessRole.parse(witness["role"].as_s), token_event_from_json(witness["event"], depth + 1, budget))
        end
        DiagnosticAnchorEvidence::RawSyntax.new(witnesses)
      when "DerivedFromOwner"
        expected_keys(fields, %w(kind))
        DiagnosticAnchorEvidence::DerivedFromOwner.new
      else
        raise ArgumentError.new("unknown diagnostic anchor evidence")
      end
    end

    private def self.anchor_use_from_json(value : JSON::Any, depth : Int32, budget : DecodeBudget) : DiagnosticAnchorUse
      fields = value.as_h
      case fields["kind"].as_s
      when "Direct"
        expected_keys(fields, %w(kind))
        DiagnosticAnchorUse::Direct.new
      when "HeadOf"
        expected_keys(fields, %w(kind rule evidence head emitter_origin))
        head_data = fields["head"].as_h
        head = case head_data["kind"].as_s
               when "Anchor"
                 expected_keys(head_data, %w(kind origin))
                 DiagnosticHead::Anchor.new(from_json(head_data["origin"], depth + 1, budget).as(Expanded)).as(DiagnosticHead)
               when "Syntax"
                 expected_keys(head_data, %w(kind form adjacent_name_origin))
                 adjacent = head_data["adjacent_name_origin"]
                 DiagnosticHead::Syntax.new(DiagnosticHeadSyntax.parse(head_data["form"].as_s),
                   adjacent.raw.nil? ? nil : from_json(adjacent, depth + 1, budget).as(Expanded)).as(DiagnosticHead)
               else
                 raise ArgumentError.new("unknown diagnostic head")
               end
        emitter = fields["emitter_origin"]
        DiagnosticAnchorUse::HeadOf.new(DiagnosticHeadRule.parse(fields["rule"].as_s),
          anchor_evidence_from_json(fields["evidence"], depth + 1, budget), head,
          emitter.raw.nil? ? nil : from_json(emitter, depth + 1, budget))
      when "PayloadOf"
        expected_keys(fields, %w(kind rule evidence owner_origin emitter_origin))
        emitter = fields["emitter_origin"]
        DiagnosticAnchorUse::PayloadOf.new(DiagnosticPayloadRule.parse(fields["rule"].as_s),
          anchor_evidence_from_json(fields["evidence"], depth + 1, budget),
          from_json(fields["owner_origin"], depth + 1, budget).as(Expanded),
          emitter.raw.nil? ? nil : from_json(emitter, depth + 1, budget))
      else
        raise ArgumentError.new("unknown diagnostic anchor use")
      end
    end

    private def self.source_token_from_json(value : JSON::Any, depth : Int32, budget : DecodeBudget) : DiagnosticSourceNameToken
      token = value.as_h
      expected_keys(token, %w(lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
      %w(context input_sha256 lexical_mode token_kind raw_text).each { |key| budget.text(token[key].as_s) }
      binding = token["binding_origin"]
      DiagnosticSourceNameToken.new(from_json(token["lexical_origin"], depth + 1, budget),
        binding.raw.nil? ? nil : from_json(binding, depth + 1, budget), token["context"].as_s,
        token["input_sha256"].as_s, token["input_bytesize"].as_i, token["input_start"].as_i,
        token["input_end"].as_i, token["lexical_mode"].as_s, token["token_kind"].as_s, token["raw_text"].as_s)
    end

    private def self.name_value_from_json(value : JSON::Any, depth : Int32, budget : DecodeBudget) : DiagnosticNameValue
      fields = value.as_h
      case fields["kind"].as_s
      when "Observed"
        expected_keys(fields, %w(kind source_token))
        DiagnosticNameValue::Observed.new(source_token_from_json(fields["source_token"], depth + 1, budget))
      when "Derived"
        expected_keys(fields, %w(kind origin))
        DiagnosticNameValue::Derived.new(from_json(fields["origin"], depth + 1, budget).as(DerivedName))
      else
        raise ArgumentError.new("unknown diagnostic name value")
      end
    end

    private def self.expected_keys(object : Hash(String, JSON::Any), keys : Array(String)) : Nil
      unless object.size == keys.size && keys.all? { |key| object.has_key?(key) }
        raise ArgumentError.new("invalid diagnostic origin fields")
      end
    end

    class DerivedName < DiagnosticOrigin
      INVALID_INTERNAL_NAMES = %w(begin nil true false yield with abstract def macro require case select if unless include extend class struct module enum while until return next break lib fun alias pointerof sizeof offsetof instance_sizeof typeof private protected asm out self in end alignof instance_alignof)
      getter source_token : DiagnosticSourceNameToken?
      getter derivation_kind : String
      getter definition_origin : DiagnosticOrigin?
      getter parameter_slot : String?
      getter parameter_index : Int32?
      getter result : String
      getter projection : String?
      getter fresh_index : Int32?
      getter rendered_text : String
      getter producer_context : String
      getter production : DiagnosticTypeSugar?
      getter sugar_result : DiagnosticTypeSugarResult?
      getter lowering_index : Int32?
      @witnesses : Array(DiagnosticSourceSyntaxToken)
      @bound_data : DiagnosticBoundProjectionData? = nil

      def producer : DiagnosticBoundProducer?; @bound_data.try(&.producer); end
      def source_fragment_sha256 : String?; @bound_data.try(&.source_fragment_sha256); end
      def source_text : String?; @bound_data.try(&.source_text); end
      def source_names : Array(DiagnosticBoundNameSource)?; @bound_data.try { |data| data.source_names.dup }; end
      def output_text : String?; @bound_data.try(&.output_text); end
      def lexical_mode : String?; @bound_data.try(&.lexical_mode); end
      def result_start : Int32?; @bound_data.try(&.result_start); end
      def result_end : Int32?; @bound_data.try(&.result_end); end
      def token_kind : String?; @bound_data.try(&.token_kind); end
      def context : String?; @bound_data.try(&.context); end

      def witnesses : Array(DiagnosticSourceSyntaxToken); @witnesses.dup; end

      def initialize(source_token : DiagnosticSourceNameToken, definition_origin : DiagnosticOrigin,
                     parameter_slot : String, parameter_index : Int32, @result : String,
                     projection : String, @fresh_index : Int32?)
        @source_token = source_token
        @derivation_kind = "ParameterLowering"
        @definition_origin = definition_origin
        @parameter_slot = parameter_slot
        @parameter_index = parameter_index
        @projection = projection
        @production = nil
        @sugar_result = nil
        @lowering_index = nil
        @witnesses = [] of DiagnosticSourceSyntaxToken
        unless source_token.context == "parameter" && source_token.binding_origin.nil? &&
               {"INSTANCE_VAR", "CLASS_VAR"}.includes?(source_token.token_kind) &&
               source_token.lexical_origin.valid_for_anchor?("Name", "parameter") &&
               definition_origin.valid_for_anchor?("Def", "keyword")
          raise ArgumentError.new("invalid derived name source")
        end
        unless {"positional", "double_splat", "block"}.includes?(parameter_slot) &&
               parameter_index >= 0 && (parameter_slot == "positional" || parameter_index == 0)
          raise ArgumentError.new("invalid derived name parameter slot")
        end
        prefix = source_token.token_kind == "INSTANCE_VAR" ? "@" : "@@"
        raw = source_token.raw_text
        raise ArgumentError.new("invalid derived name prefix") unless raw.starts_with?(prefix)
        stem = raw.byte_slice(prefix.bytesize, raw.bytesize - prefix.bytesize)
        invalid = INVALID_INTERNAL_NAMES.includes?(stem)
        @producer_context = case @result
                            when "Argument" then "parameter"
                            when "Target" then source_token.token_kind == "INSTANCE_VAR" ? "instance_variable" : "class_variable"
                            when "LocalValue" then "local_reference"
                            when "DefaultExternal" then "named_entry"
                            else raise ArgumentError.new("invalid derived name result")
                            end
        @rendered_text = case projection
                         when "Whole"
                           raise ArgumentError.new("invalid whole name derivation") unless @result == "Target" && @fresh_index.nil?
                           raw
                         when "StripVariablePrefix"
                           unless ((@result == "Argument" || @result == "LocalValue") && !invalid && @fresh_index.nil?) ||
                                  (@result == "DefaultExternal" && invalid && @fresh_index.nil?)
                             raise ArgumentError.new("invalid prefix name derivation")
                           end
                           stem
                         when "FreshParameterName"
                           index = @fresh_index
                           unless invalid && index && index >= 0 && {"Argument", "LocalValue"}.includes?(@result)
                             raise ArgumentError.new("invalid fresh name derivation")
                           end
                           "__arg#{index}"
                         else
                           raise ArgumentError.new("unknown name projection")
                         end
        set_graph_bounds!(1024_u64 + source_token.raw_text.bytesize.to_u64 * 6, [source_token.lexical_origin, definition_origin] of DiagnosticOrigin)
      end

      def self.regex_match_index(source_token : DiagnosticSourceNameToken, result : String) : DerivedName
        new(source_token, result)
      end

      def initialize(source_token : DiagnosticSourceNameToken, @result : String)
        @source_token = source_token
        @derivation_kind = "RegexMatchIndex"
        @definition_origin = nil
        @parameter_slot = nil
        @parameter_index = nil
        @projection = nil
        @fresh_index = nil
        @production = nil
        @sugar_result = nil
        @lowering_index = nil
        @witnesses = [] of DiagnosticSourceSyntaxToken
        unless source_token.context == "regex_match_index" && source_token.binding_origin.nil? &&
               source_token.lexical_origin.valid_for_anchor?("Name", "regex_match_index")
          raise ArgumentError.new("invalid regex-match derivation source")
        end
        case @result
        when "MatchData"
          @producer_context = "special_global"
          @rendered_text = "$~"
        when "Lookup"
          @producer_context = "method_name"
          @rendered_text = source_token.raw_text.ends_with?("?") ? "[]?" : "[]"
        else
          raise ArgumentError.new("invalid regex-match derivation result")
        end
        set_graph_bounds!(1024_u64 + source_token.raw_text.bytesize.to_u64 * 6, [source_token.lexical_origin] of DiagnosticOrigin)
      end

      def self.type_sugar(production : DiagnosticTypeSugar, witnesses : Array(DiagnosticSourceSyntaxToken),
                          result : DiagnosticTypeSugarResult, lowering_index : Int32) : DerivedName
        new(production, witnesses, result, lowering_index)
      end

      def initialize(@production : DiagnosticTypeSugar, witnesses : Array(DiagnosticSourceSyntaxToken),
                     result : DiagnosticTypeSugarResult, @lowering_index : Int32)
        @source_token = nil
        @derivation_kind = "TypeSugar"
        @definition_origin = nil
        @parameter_slot = nil
        @parameter_index = nil
        @projection = nil
        @fresh_index = nil
        @sugar_result = result
        @result = result.to_s
        @producer_context = result == DiagnosticTypeSugarResult::Self ? "type_self" : "path_segment"
        @rendered_text = result == DiagnosticTypeSugarResult::Self ? "self" : result.to_s
        @witnesses = witnesses.dup
        production = @production.not_nil!
        expected, allowed_results, allowed_indices = case production
          when DiagnosticTypeSugar::Pointer then {["*"], [DiagnosticTypeSugarResult::Pointer], [0]}
          when DiagnosticTypeSugar::DoublePointer then {["**"], [DiagnosticTypeSugarResult::Pointer], [0, 1]}
          when DiagnosticTypeSugar::NilableType then {["?"], [DiagnosticTypeSugarResult::Nil], [0]}
          when DiagnosticTypeSugar::NilableExpression then {["?"], [DiagnosticTypeSugarResult::Union, DiagnosticTypeSugarResult::Nil], [0]}
          when DiagnosticTypeSugar::SelfNilableType then {["self?"], [DiagnosticTypeSugarResult::Nil, DiagnosticTypeSugarResult::Self], [0]}
          when DiagnosticTypeSugar::StaticArray then {["[", "]"], [DiagnosticTypeSugarResult::StaticArray], [0]}
          when DiagnosticTypeSugar::Tuple then {["{", "}"], [DiagnosticTypeSugarResult::Tuple], [0]}
          when DiagnosticTypeSugar::NamedTuple then {["{", "}"], [DiagnosticTypeSugarResult::NamedTuple], [0]}
          when DiagnosticTypeSugar::NilPredicate then {["nil?"], [DiagnosticTypeSugarResult::Nil], [0]}
          else raise ArgumentError.new("unknown type-sugar production")
        end
        unless @witnesses.map(&.raw_text) == expected && allowed_results.includes?(result) && allowed_indices.includes?(@lowering_index.not_nil!)
          raise ArgumentError.new("invalid type-sugar derivation")
        end
        @witnesses.each_cons_pair do |left, right|
          unless left.input_sha256 == right.input_sha256 && left.input_bytesize == right.input_bytesize &&
                 left.lexical_mode == right.lexical_mode && left.input_end <= right.input_start
            raise ArgumentError.new("inconsistent type-sugar witnesses")
          end
        end
        parents = @witnesses.map(&.lexical_origin)
        set_graph_bounds!(1024_u64 + @witnesses.sum { |w| w.raw_text.bytesize.to_u64 * 6 + 256_u64 }, parents)
        @witnesses.each_cons_pair do |left, right|
          same_input = case left_origin = left.lexical_origin
                       when Written
                         right_origin = right.lexical_origin.as?(Written)
                         right_origin && left_origin.source_module == right_origin.source_module && left_origin.source_file == right_origin.source_file
                       when Expanded
                         right_origin = right.lexical_origin.as?(Expanded)
                         right_origin && left_origin.invocation_origin == right_origin.invocation_origin &&
                           left_origin.macro_definition_origin == right_origin.macro_definition_origin &&
                           left_origin.expansion_guard == right_origin.expansion_guard
                       else
                         false
                       end
          raise ArgumentError.new("type-sugar witnesses use different inputs") unless same_input
        end
      end

      def self.bound_projection(producer : DiagnosticBoundProducer, source_fragment_sha256 : String, source_text : String,
                                source_names : Array(DiagnosticBoundNameSource), output_text : String, lexical_mode : String,
                                result_start : Int32, result_end : Int32, token_kind : String, context : String) : DerivedName
        new(DiagnosticBoundProjectionData.new(producer, source_fragment_sha256, source_text, source_names.dup,
          output_text, lexical_mode, result_start, result_end, token_kind, context))
      end

      def initialize(data : DiagnosticBoundProjectionData)
        @source_token = nil
        @derivation_kind = "BoundProjection"
        @definition_origin = nil
        @parameter_slot = nil
        @parameter_index = nil
        @result = ""
        @projection = nil
        @fresh_index = nil
        @production = nil
        @sugar_result = nil
        @lowering_index = nil
        @witnesses = [] of DiagnosticSourceSyntaxToken
        @bound_data = DiagnosticBoundProjectionData.new(data.producer, data.source_fragment_sha256, data.source_text,
          data.source_names.dup, data.output_text, data.lexical_mode, data.result_start, data.result_end, data.token_kind, data.context)
        unless data.source_fragment_sha256.bytesize == 64 &&
               data.source_fragment_sha256.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) } &&
               data.source_text.valid_encoding? && data.output_text.valid_encoding? &&
               data.result_start >= 0 && data.result_end > data.result_start && data.result_end <= data.output_text.bytesize
          raise ArgumentError.new("invalid bound projection inputs")
        end
        parents = [] of DiagnosticOrigin
        own = 2048_u64 + data.source_text.bytesize.to_u64 * 6 + data.output_text.bytesize.to_u64 * 6
        cursor = 0
        data.source_names.each do |entry|
          unless entry.start_offset >= cursor && entry.end_offset > entry.start_offset && entry.end_offset <= data.source_text.bytesize &&
                 data.source_text.byte_slice(entry.start_offset, entry.end_offset - entry.start_offset) == entry.name.rendered_text
            raise ArgumentError.new("invalid bound source name")
          end
          cursor = entry.end_offset
          own += entry.name.graph_bytes + 256_u64
          raise ArgumentError.new("bound projection graph exceeds size limit") if own > MAX_UNFOLDED_BYTES
          raise ArgumentError.new("bound source graph exceeds depth limit") if entry.name.artifact_origin.graph_depth + 1 > MAX_DEPTH
        end
        actual = case producer = data.producer
                 when DiagnosticBoundProducer::StripRoot
                   prefix = "#{producer.root}::"
                   raise ArgumentError.new("invalid bound root removal") if producer.root.empty? || !data.source_text.starts_with?(prefix) || data.source_names.empty?
                   data.source_text.byte_slice(prefix.bytesize, data.source_text.bytesize - prefix.bytesize)
                 when DiagnosticBoundProducer::ForeignType
                   prefix = producer.source_name
                   raise ArgumentError.new("invalid foreign type projection") if producer.module_name.empty? || prefix.empty? || producer.qualified_name.empty? || !data.source_text.starts_with?(prefix) || data.source_names.empty?
                   suffix = data.source_text.byte_slice(prefix.bytesize, data.source_text.bytesize - prefix.bytesize)
                   if !suffix.empty? && (suffix[0].ascii_alphanumeric? || suffix[0] == '_')
                     raise ArgumentError.new("foreign type projection lacks a name boundary")
                   end
                   producer.qualified_name + suffix
                 when DiagnosticBoundProducer::AliasType
                   raise ArgumentError.new("invalid alias type projection") unless !producer.owner.empty? && !producer.name.empty? && !producer.resolved_type.empty? && data.source_text == producer.name && !data.source_names.empty?
                   producer.resolved_type
                 when DiagnosticBoundProducer::SelfReturn
                   unless producer.method_name == "new" && producer.receiver == "self" && data.source_text == producer.owner_type && !data.source_names.empty?
                     raise ArgumentError.new("invalid self-return projection")
                   end
                   "self"
                 when DiagnosticBoundProducer::SemanticSignatureType
                   unless producer.definition_origin.valid_for_anchor?("Def", "keyword") && data.source_text.empty? && data.source_names.empty? &&
                          !producer.semantic_type.empty? &&
                          ((producer.field == "return_type" && producer.parameter_index.nil?) ||
                           (producer.field == "parameter_restriction" && producer.parameter_index.try(&.>=(0))))
                     raise ArgumentError.new("invalid semantic signature projection")
                   end
                   parents << producer.definition_origin
                   producer.semantic_type
                 when DiagnosticBoundProducer::UninitializedClassVar
                   unless producer.declaration_origin.valid_for_anchor?("Name", "class_variable") &&
                          !producer.owner_type.empty? && !producer.variable_name.empty? && !producer.semantic_type.empty? &&
                          data.source_text.empty? && data.source_names.empty?
                     raise ArgumentError.new("invalid class-variable projection")
                   end
                   parents << producer.declaration_origin
                   "uninitialized #{producer.semantic_type}"
                 when DiagnosticBoundProducer::ConstantAccessor
                   unless producer.definition_origin.valid_for_anchor?("Def", "keyword") &&
                          producer.definition_origin.is_a?(DiagnosticOrigin::Synthetic) &&
                          producer.definition_origin.synthesis_kind == "constant_accessor" &&
                          producer.definition_origin.structural_slot == "getter" &&
                          !producer.constant_name.empty? && data.source_text.empty? && data.source_names.empty?
                     raise ArgumentError.new("invalid constant accessor projection")
                   end
                   parents << producer.definition_origin
                   case producer.part
                   when "Name" then "#{producer.prefix}#{producer.constant_name}".downcase
                   when "Receiver" then "self"
                   else raise ArgumentError.new("invalid accessor projection part")
                   end
                 else
                   raise ArgumentError.new("unknown bound projection producer")
                 end
        raise ArgumentError.new("bound output differs from closed projection") unless actual == data.output_text
        permitted = if (producer = data.producer).is_a?(DiagnosticBoundProducer::ConstantAccessor)
                      producer.part == "Name" ? {"definition_name"} : {"local_reference"}
                    else
                      {"path_segment", "named_entry", "type_self"}
                    end
        raise ArgumentError.new("invalid bound projection context") unless permitted.includes?(data.context)
        lex_context = data.context == "definition_name" ? DiagnosticRenderedLexContext::DefOrMacroName : DiagnosticRenderedLexContext::TypeName
        observed = DiagnosticRenderedTokens.observe_one(data.output_text, data.result_start, data.result_end, data.lexical_mode, lex_context)
        unless observed.token_kind == data.token_kind &&
               DiagnosticSourceNameToken.valid_token?(data.token_kind, observed.token_text, data.lexical_mode, data.context)
          raise ArgumentError.new("invalid bound result token")
        end
        @producer_context = data.context
        @rendered_text = observed.token_text
        set_graph_bounds!(own, parents)
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        if @derivation_kind == "RegexMatchIndex" && @result == "Lookup"
          kind == "Call" && role == "method"
        else
          kind == "Name" && role == @producer_context
        end
      end

      def_equals_and_hash @derivation_kind, @source_token, @definition_origin, @parameter_slot, @parameter_index, @result, @projection, @fresh_index, @production, @sugar_result, @lowering_index, @witnesses

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "DerivedName"
          json.field "derivation_kind", @derivation_kind
          if @derivation_kind == "TypeSugar"
            json.field "production", @production.not_nil!.to_s
            json.field "witnesses" do
              json.array { @witnesses.each { |witness| witness.to_json(json) } }
            end
            json.field "result", @result
            json.field "lowering_index", @lowering_index
          else
            json.field "source_token", @source_token
            if @derivation_kind == "ParameterLowering"
              json.field "definition_origin", @definition_origin
              json.field "parameter_slot", @parameter_slot
              json.field "parameter_index", @parameter_index
              json.field "result", @result
              json.field "projection", @projection
              json.field "fresh_index", @fresh_index
            else
              json.field "result", @result
            end
          end
        end
      end
    end

    class Written < DiagnosticOrigin
      getter source_module : String
      getter source_file : String
      getter input_byte_offset : Int32
      getter anchor_kind : String
      getter role : String

      def initialize(source_module : String, source_file : String, input_byte_offset : Int32, anchor_kind : String, role : String)
        @source_module = DiagnosticOrigin.require_text(source_module, "source module")
        @source_file = DiagnosticOrigin.require_text(source_file, "source file")
        @input_byte_offset = DiagnosticOrigin.require_offset(input_byte_offset, "input offset")
        @anchor_kind = DiagnosticOrigin.require_text(anchor_kind, "anchor kind")
        @role = DiagnosticOrigin.require_text(role, "role")
        own = %({"kind":"Written","source_identity":{"module":,"file":},"input_byte_offset":,"anchor_kind":,"role":}).bytesize.to_u64
        own += DiagnosticOrigin.json_string_size(@source_module) + DiagnosticOrigin.json_string_size(@source_file)
        own += @input_byte_offset.to_s.bytesize.to_u64 + DiagnosticOrigin.json_string_size(@anchor_kind) + DiagnosticOrigin.json_string_size(@role)
        set_graph_bounds!(own, [] of DiagnosticOrigin)
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        @anchor_kind == kind && @role == role
      end

      def_equals_and_hash @source_module, @source_file, @input_byte_offset, @anchor_kind, @role

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Written"
          json.field "source_identity" do
            json.object do
              json.field "module", @source_module
              json.field "file", @source_file
            end
          end
          json.field "input_byte_offset", @input_byte_offset
          json.field "anchor_kind", @anchor_kind
          json.field "role", @role
        end
      end
    end

    class Expanded < DiagnosticOrigin
      getter invocation_origin : DiagnosticOrigin
      getter macro_definition_origin : DiagnosticOrigin
      getter expansion_guard : String
      getter anchor_kind : String
      getter role : String
      getter name_context : String?
      getter token_event : DiagnosticTokenEvent
      getter anchor_use : DiagnosticAnchorUse

      def initialize(@invocation_origin : DiagnosticOrigin, @macro_definition_origin : DiagnosticOrigin,
                     @expansion_guard : String, @anchor_kind : String, @role : String, @name_context : String?,
                     @token_event : DiagnosticTokenEvent, @anchor_use : DiagnosticAnchorUse)
        invocation_valid = @invocation_origin.valid_for_anchor?("Call", "method") ||
                           @invocation_origin.valid_for_anchor?("MacroDirective", "control") ||
                           @invocation_origin.valid_for_anchor?("MacroDirective", "expression") ||
                           @invocation_origin.valid_for_anchor?("Include", "keyword") ||
                           @invocation_origin.valid_for_anchor?("Extend", "keyword") ||
                           @invocation_origin.valid_for_anchor?("ClassDef", "keyword") ||
                           @invocation_origin.valid_for_anchor?("Def", "keyword") ||
                           @invocation_origin.valid_for_anchor?("Macro", "keyword")
        unless invocation_valid && @macro_definition_origin.valid_for_anchor?("Macro", "keyword")
          raise ArgumentError.new("unsupported diagnostic macro invocation or definition origin")
        end
        unless @expansion_guard.starts_with?("sha256:") && @expansion_guard.bytesize == 71 &&
               @expansion_guard.byte_slice(7, 64).each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) }
          raise ArgumentError.new("invalid diagnostic expansion guard")
        end
        raise ArgumentError.new("invalid diagnostic anchor") if @anchor_kind.empty? || @role.empty?
        if @token_event.selection.signed_number_sign? && !(@anchor_use.is_a?(DiagnosticAnchorUse::Direct) && @anchor_kind == "Call" && @role == "method" && @name_context.nil?)
          raise ArgumentError.new("invalid signed-number anchor use")
        end
        if context = @name_context
          unless @anchor_use.is_a?(DiagnosticAnchorUse::Direct) &&
                 DiagnosticSourceNameToken.valid_token?(@token_event.token_kind, @token_event.selected_text, @token_event.lexical_mode, context) &&
                 ((@anchor_kind == "Name" && @role == context) || (@anchor_kind == "Call" && @role == "method" && context == "method_name"))
            raise ArgumentError.new("invalid receiving diagnostic name role")
          end
        end

        parents = [@invocation_origin, @macro_definition_origin] of DiagnosticOrigin
        own = 1024_u64 + @token_event.graph_bytes + DiagnosticOrigin.json_string_size(@anchor_kind) + DiagnosticOrigin.json_string_size(@role)
        raise ArgumentError.new("diagnostic origin graph exceeds depth limit") if @token_event.graph_depth + 1 > MAX_DEPTH
        case use = @anchor_use
        when DiagnosticAnchorUse::Direct
          @token_event.byte_parts.each do |part|
            case part
            when DiagnosticEmissionPart::AstAnchor
              unless @token_event.byte_parts.size == 1 && part.source_origin.valid_for_anchor?(@anchor_kind, @role)
                raise ArgumentError.new("invalid structural macro splice")
              end
            when DiagnosticEmissionPart::NameSplice
              raise ArgumentError.new("name splice without name context") unless @name_context
            end
          end
        when DiagnosticAnchorUse::HeadOf
          use.emitter_origin.try { |emitter| parents << emitter }
          expected = case use.rule
                     when DiagnosticHeadRule::NamedArrayHead then {"Literal", "array"}
                     when DiagnosticHeadRule::NamedHashHead then {"Literal", "hash"}
                     when DiagnosticHeadRule::ConstantAssignHead, DiagnosticHeadRule::ConstantTypeHead then {"Assign", "constant"}
                     when DiagnosticHeadRule::MultiAssignHead then {"Literal", "multiassign"}
                     else raise ArgumentError.new("invalid head rule")
                     end
          raise ArgumentError.new("head role mismatch") unless {@anchor_kind, @role} == expected && @name_context.nil?
          case evidence = use.evidence
          when DiagnosticAnchorEvidence::Spliced
            raise ArgumentError.new("head source role mismatch") unless evidence.source_origin.valid_for_anchor?(@anchor_kind, @role)
            parents << evidence.source_origin
          when DiagnosticAnchorEvidence::Constructed
          when DiagnosticAnchorEvidence::RawSyntax
            expected_witnesses = case use.rule
                                 when DiagnosticHeadRule::NamedArrayHead, DiagnosticHeadRule::NamedHashHead
                                   [{DiagnosticWitnessRole::Open, "{"}]
                                 when DiagnosticHeadRule::ConstantAssignHead
                                   [{DiagnosticWitnessRole::Equals, "="}]
                                 when DiagnosticHeadRule::ConstantTypeHead
                                   [{DiagnosticWitnessRole::Colon, ":"}, {DiagnosticWitnessRole::Equals, "="}]
                                 when DiagnosticHeadRule::MultiAssignHead
                                   if (head = use.head).is_a?(DiagnosticHead::Syntax) && head.form == DiagnosticHeadSyntax::FirstSplat
                                     [{DiagnosticWitnessRole::Splat, "*"}, {DiagnosticWitnessRole::Equals, "="}]
                                   else
                                     [{DiagnosticWitnessRole::Comma, ","}, {DiagnosticWitnessRole::Equals, "="}]
                                   end
                                 else
                                   raise ArgumentError.new("unknown raw witness rule")
                                 end
            witnesses = evidence.witnesses
            raise ArgumentError.new("wrong raw witness count") unless witnesses.size == expected_witnesses.size
            cursor = @token_event.selected_end
            witnesses.each_with_index do |witness, index|
              event = witness.event
              role, spelling = expected_witnesses[index]
              first_splat = index == 0 && role == DiagnosticWitnessRole::Splat &&
                            event == @token_event
              unless witness.role == role && event.selection.whole? && event.token_kind == spelling &&
                     event.token_text == spelling && event.lexical_mode == @token_event.lexical_mode &&
                     (first_splat || event.selected_start >= cursor)
                raise ArgumentError.new("invalid raw syntax witness")
              end
              unless event.byte_parts.all? { |part|
                part.is_a?(DiagnosticEmissionPart::Generated) &&
                  {DiagnosticMacroProducer::MacroTemplate, DiagnosticMacroProducer::MacroId,
                   DiagnosticMacroProducer::MacroVar, DiagnosticMacroProducer::MacroVerbatim,
                   DiagnosticMacroProducer::YieldWrapper, DiagnosticMacroProducer::SemanticPrinter}.includes?(part.producer)
              }
                raise ArgumentError.new("raw syntax witness lacks raw producer")
              end
              own += event.graph_bytes
              raise ArgumentError.new("raw witness graph exceeds depth limit") if event.graph_depth + 1 > MAX_DEPTH
              cursor = event.selected_end
            end
          else
            raise ArgumentError.new("invalid head evidence")
          end
          case head = use.head
          when DiagnosticHead::Anchor
            child = head.origin.as?(Expanded) || raise ArgumentError.new("head is not an expanded child")
            parents << child
          when DiagnosticHead::Syntax
            parents << head.adjacent_name_origin.not_nil! if head.adjacent_name_origin
          end
        when DiagnosticAnchorUse::PayloadOf
          use.emitter_origin.try { |emitter| parents << emitter }
          raise ArgumentError.new("payload role mismatch") unless @anchor_kind == "Literal" && @role == "interpolation" && @name_context.nil?
          owner = use.owner_origin.as?(Expanded) || raise ArgumentError.new("payload owner is not expanded")
          owner_role = use.rule == DiagnosticPayloadRule::RegexInterpolationPayload ? {"Literal", "regex"} : {"Call", "method"}
          raise ArgumentError.new("payload owner role mismatch") unless owner.valid_for_anchor?(*owner_role)
          parents << owner
          case evidence = use.evidence
          when DiagnosticAnchorEvidence::Spliced
            raise ArgumentError.new("payload source role mismatch") unless evidence.source_origin.valid_for_anchor?("Literal", "interpolation")
            parents << evidence.source_origin
          when DiagnosticAnchorEvidence::Constructed, DiagnosticAnchorEvidence::DerivedFromOwner
          else
            raise ArgumentError.new("invalid payload evidence")
          end
        end
        set_graph_bounds!(own, parents)

        case use = @anchor_use
        when DiagnosticAnchorUse::HeadOf
          case head = use.head
          when DiagnosticHead::Anchor
            child = head.origin.as(Expanded)
            unless child.invocation_origin == @invocation_origin && child.macro_definition_origin == @macro_definition_origin &&
                   child.expansion_guard == @expansion_guard && child.token_event == @token_event
              raise ArgumentError.new("head event mismatch")
            end
            allowed = if use.rule == DiagnosticHeadRule::MultiAssignHead
                        (child.anchor_kind == "Name" && {"path_segment", "local_reference", "instance_variable", "class_variable", "special_global"}.includes?(child.role)) ||
                          (child.anchor_kind == "Call" && child.role == "method") ||
                          (child.anchor_kind == "Literal" && {"array", "hash", "regex", "interpolation", "range", "case", "select"}.includes?(child.role)) ||
                          ({"ProcLiteral", "ProcPointer"}.includes?(child.anchor_kind) && child.role == "arrow") ||
                          (child.anchor_kind == "Cast" && child.role == "keyword")
                      else
                        child.anchor_kind == "Name" && child.role == "path_segment"
                      end
            unless allowed && child.anchor_use.is_a?(DiagnosticAnchorUse::Direct)
              raise ArgumentError.new("invalid head child role")
            end
          when DiagnosticHead::Syntax
            expected_text = case head.form
                            when DiagnosticHeadSyntax::GlobalPathPrefix then "::"
                            when DiagnosticHeadSyntax::FirstSplat then "*"
                            when DiagnosticHeadSyntax::FirstUnderscore then "_"
                            when DiagnosticHeadSyntax::ParenthesizedFirstTarget then "("
                            else raise ArgumentError.new("invalid syntax head")
                            end
            unless @token_event.selection.whole? && @token_event.token_kind == expected_text && @token_event.token_text == expected_text
              raise ArgumentError.new("syntax head token mismatch")
            end
            if head.form == DiagnosticHeadSyntax::GlobalPathPrefix
              adjacent = head.adjacent_name_origin.not_nil!
              unless adjacent.anchor_use.is_a?(DiagnosticAnchorUse::Direct) &&
                     adjacent.valid_for_anchor?("Name", "path_segment") && adjacent.token_event.token_kind == "CONST" &&
                     adjacent.token_event.selected_start == @token_event.selected_end &&
                     adjacent.token_event.lexical_mode == @token_event.lexical_mode &&
                     adjacent.invocation_origin == @invocation_origin && adjacent.macro_definition_origin == @macro_definition_origin &&
                     adjacent.expansion_guard == @expansion_guard
                raise ArgumentError.new("invalid global prefix adjacency")
              end
            elsif use.rule != DiagnosticHeadRule::MultiAssignHead
              raise ArgumentError.new("invalid punctuation head rule")
            end
          end
        when DiagnosticAnchorUse::PayloadOf
          owner = use.owner_origin.as(Expanded)
          unless owner.invocation_origin == @invocation_origin && owner.macro_definition_origin == @macro_definition_origin &&
                 owner.expansion_guard == @expansion_guard && owner.token_event == @token_event
            raise ArgumentError.new("payload event mismatch")
          end
          unless owner.anchor_use.is_a?(DiagnosticAnchorUse::Direct) && @token_event.selection.whole? && @token_event.token_kind == "DELIMITER_START"
            raise ArgumentError.new("invalid payload owner event")
          end
          openers = if use.rule == DiagnosticPayloadRule::RegexInterpolationPayload
                      {"/", "%r(", "%r<", "%r[", "%r{", "%r|"}
                    else
                      {"`", "%x(", "%x<", "%x[", "%x{", "%x|"}
                    end
          raise ArgumentError.new("invalid payload opener") unless openers.includes?(@token_event.token_text)
          if use.evidence.is_a?(DiagnosticAnchorEvidence::DerivedFromOwner)
            unless @token_event.byte_parts.all? { |part|
              part.is_a?(DiagnosticEmissionPart::Generated) &&
                {DiagnosticMacroProducer::MacroTemplate, DiagnosticMacroProducer::MacroId, DiagnosticMacroProducer::MacroVar,
                 DiagnosticMacroProducer::MacroVerbatim, DiagnosticMacroProducer::YieldWrapper, DiagnosticMacroProducer::SemanticPrinter}.includes?(part.producer)
            }
              raise ArgumentError.new("derived payload lacks raw owner")
            end
          end
        end
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        @anchor_kind == kind && @role == role
      end

      def_equals_and_hash @invocation_origin, @macro_definition_origin, @expansion_guard, @anchor_kind, @role, @name_context, @token_event, @anchor_use

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Expanded"
          json.field "invocation_origin", @invocation_origin
          json.field "macro_definition_origin", @macro_definition_origin
          json.field "expansion_guard", @expansion_guard
          json.field "anchor_kind", @anchor_kind
          json.field "role", @role
          json.field "name_context", @name_context
          json.field "token_event", @token_event
          json.field "anchor_use", @anchor_use
        end
      end
    end

    class Synthetic < DiagnosticOrigin
      getter parent_origin : DiagnosticOrigin
      getter synthesis_kind : String
      getter structural_slot : String

      def initialize(@parent_origin : DiagnosticOrigin, synthesis_kind : String, structural_slot : String)
        @synthesis_kind = DiagnosticOrigin.require_text(synthesis_kind, "synthesis kind")
        @structural_slot = DiagnosticOrigin.require_text(structural_slot, "structural slot")
        own = %({"kind":"Synthetic","parent_origin":,"synthesis_kind":,"structural_slot":}).bytesize.to_u64
        own += DiagnosticOrigin.json_string_size(@synthesis_kind) + DiagnosticOrigin.json_string_size(@structural_slot)
        set_graph_bounds!(own, [@parent_origin] of DiagnosticOrigin)
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        if kind == "Cast" && role == "keyword" && @synthesis_kind == "select_cast"
          label, separator, text = @structural_slot.partition(':')
          index = text.to_i?
          return label == "arm" && separator == ":" && !index.nil? && index >= 0 && index.to_s == text &&
            @parent_origin.valid_for_anchor?("Literal", "select")
        end
        if kind == "Literal" && role == "interpolation" && @synthesis_kind == "cast_error_interpolation" && @structural_slot == "message"
          return @parent_origin.valid_for_anchor?("Cast", "keyword")
        end
        if kind == "Block" && role == "opener" && @synthesis_kind == "literal_expansion"
          parts = @structural_slot.split(':')
          index = parts[2]?.try(&.to_i?)
          return parts.size == 3 && parts[0] == "array" && parts[1] == "block" &&
            !index.nil? && index >= 0 && index.to_s == parts[2] &&
            @parent_origin.valid_for_anchor?("Literal", "array")
        end
        if kind == "Literal" && @synthesis_kind == "literal_expansion_node"
          if @structural_slot == "derive:fields" && role == "array"
            return @parent_origin.valid_for_anchor?("Call", "method")
          end
          if @structural_slot == "select:multiassign" && role == "multiassign"
            return @parent_origin.valid_for_anchor?("Literal", "select")
          elsif @structural_slot == "select:case" && role == "case"
            return @parent_origin.valid_for_anchor?("Literal", "select")
          elsif @structural_slot == "regex:interpolation" && role == "interpolation"
            return @parent_origin.valid_for_anchor?("Literal", "regex")
          elsif @structural_slot == "command:interpolation" && role == "interpolation"
            return @parent_origin.valid_for_anchor?("Call", "method")
          elsif @structural_slot.starts_with?("array:interpolation:") && role == "interpolation"
            text = @structural_slot.byte_slice("array:interpolation:".bytesize)
            index = text.to_i?
            return !index.nil? && index >= 0 && index.to_s == text &&
              @parent_origin.valid_for_anchor?("Literal", "array")
          elsif @structural_slot.starts_with?("block_unpack:") && role == "multiassign"
            return false unless @parent_origin.valid_for_anchor?("Block", "opener") ||
                                @parent_origin.valid_for_anchor?("Block", "ampersand")
            indices = @structural_slot.byte_slice("block_unpack:".bytesize).split(':')
            return !indices.empty? && indices.all? do |text|
              index = text.to_i?
              !index.nil? && index >= 0 && index.to_s == text
            end
          elsif @structural_slot.starts_with?("multiassign:range:") && role == "range"
            text = @structural_slot.byte_slice("multiassign:range:".bytesize)
            index = text.to_i?
            return !index.nil? && index >= 0 && index.to_s == text &&
              @parent_origin.valid_for_anchor?("Literal", "multiassign")
          end
          return false
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "literal_expansion"
          parts = @structural_slot.split(':')
          return false unless parts.size >= 2 && @parent_origin.valid_for_anchor?("Literal", parts[0])
          if parts.size == 2
            return case parts[0]
            when "array"         then {"constructor", "buffer"}.includes?(parts[1])
            when "hash", "range" then parts[1] == "constructor"
            when "regex"         then {"constructor", "options", "compile"}.includes?(parts[1])
            when "interpolation" then parts[1] == "call"
            when "select"        then {"select", "invalid"}.includes?(parts[1])
            when "multiassign"   then {"size", "compare", "error", "raise"}.includes?(parts[1])
            else                      false
            end
          end
          if parts.size == 5 && parts[0] == "case" && parts[1] == "compare"
            return parts[2..4].all? do |text|
              index = text.to_i?
              !index.nil? && index >= 0 && index.to_s == text
            end
          end
          return false unless parts.size == 3
          index = parts[2].to_i?
          return false unless index && index >= 0 && index.to_s == parts[2]
          return case parts[0]
          when "array"       then {"concat", "append", "store", "element_type", "each", "each_body"}.includes?(parts[1])
          when "hash"        then parts[1] == "store"
          when "multiassign" then parts[1] == "index"
          else                    false
          end
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "proc_pointer_invoke" && @structural_slot == "call"
          return @parent_origin.valid_for_anchor?("ProcPointer", "arrow")
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "recover_panic" &&
           (@structural_slot == "message" || @structural_slot == "raise")
          return @parent_origin.valid_for_anchor?("Call", "method")
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "group_lowering"
          return false unless @parent_origin.valid_for_anchor?("Call", "method")
          return true if @structural_slot == "join" || @structural_slot == "first_failure"
          label, separator, text = @structural_slot.partition(':')
          index = text.to_i?
          return separator == ":" && {"value", "fiber", "object_id", "compare"}.includes?(label) &&
            !index.nil? && index >= 0 && index.to_s == text
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "defer_runtime" &&
           (@structural_slot == "push" || @structural_slot == "pop")
          return @parent_origin.valid_for_anchor?("Defer", "keyword")
        end
        if kind == "Call" && role == "method" && @synthesis_kind == "compound_assignment" &&
           (@structural_slot == "getter" || @structural_slot == "setter")
          return @parent_origin.valid_for_anchor?("Call", "method")
        end
        if kind == "Def" && role == "keyword" && @synthesis_kind == "constant_accessor" && @structural_slot == "getter"
          return @parent_origin.valid_for_anchor?("Assign", "constant")
        end
        if kind == "Macro" && role == "keyword" && @synthesis_kind == "inline_macro_definition" && @structural_slot == "macro"
          return @parent_origin.valid_for_anchor?("MacroDirective", "control") ||
            @parent_origin.valid_for_anchor?("MacroDirective", "expression")
        end
        return false unless kind == "ProcLiteral" && role == "arrow"
        case {@synthesis_kind, @structural_slot}
        when {"block_to_proc", "proc"}
          @parent_origin.valid_for_anchor?("Block", "opener") || @parent_origin.valid_for_anchor?("Block", "ampersand")
        when {"proc_pointer", "proc"}
          @parent_origin.valid_for_anchor?("ProcPointer", "arrow")
        when {"defer", "cleanup"}
          @parent_origin.valid_for_anchor?("Defer", "keyword")
        else
          false
        end
      end

      def valid_for_binding? : Bool
        if @synthesis_kind == "local_binding"
          return @structural_slot == "assignment" && @parent_origin.valid_for_anchor?("Call", "method")
        end
        return false unless @structural_slot.starts_with?("index:")
        index_text = @structural_slot.byte_slice(6)
        index = index_text.to_i?
        return false unless index && index >= 0 && index.to_s == index_text
        case @synthesis_kind
        when "parameter_binding"
          @parent_origin.valid_for_anchor?("Def", "keyword")
        when "block_parameter"
          @parent_origin.valid_for_anchor?("Block", "opener") || @parent_origin.valid_for_anchor?("Block", "ampersand")
        when "proc_parameter"
          @parent_origin.valid_for_anchor?("ProcLiteral", "arrow")
        else
          false
        end
      end

      def_equals_and_hash @parent_origin, @synthesis_kind, @structural_slot

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Synthetic"
          json.field "parent_origin", @parent_origin
          json.field "synthesis_kind", @synthesis_kind
          json.field "structural_slot", @structural_slot
        end
      end
    end
  end
end
