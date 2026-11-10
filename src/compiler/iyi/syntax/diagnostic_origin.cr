require "json"

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
  end

  record DiagnosticNameSlot, kind : DiagnosticNameSlotKind, index : Int32 = 0 do
    def initialize(@kind : DiagnosticNameSlotKind, @index : Int32 = 0)
      raise ArgumentError.new("negative diagnostic name slot index") if @index < 0
      if @index != 0 && !@kind.path_segment? && !@kind.type_parameter? && !@kind.named_entry?
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
                when "path_segment", "type_parameter" then kind == "CONST"
                when "named_entry"                   then {"IDENT", "CONST"}.includes?(kind)
                when "enum_member"                   then kind == "CONST"
                when "special_global"                then {"$~", "$?"}.includes?(kind)
                when "regex_match_index"             then kind == "GLOBAL_MATCH_DATA_INDEX"
                else                                      false
                end
      return false unless allowed && {"Crystal", "Iyi"}.includes?(mode) && raw.valid_encoding?
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
              "enum_member", "special_global", "regex_match_index"}.includes?(@context)
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
        unless lexical_origin.token_event.input_start == @input_start && lexical_origin.expansion_guard == "sha256:#{@input_sha256}"
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
        unless origin.token_event.input_start == @input_start && origin.expansion_guard == "sha256:#{@input_sha256}"
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
        unless @token_kind == "NUMBER" && (@token_text.starts_with?("+") || @token_text.starts_with?("-")) && @token_text.bytesize > 1
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
        raise ArgumentError.new("invalid constructed anchor producer") unless @producer == DiagnosticMacroProducer::ConstructedAst
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
        when PayloadOf
          json.field "kind", "PayloadOf"
          json.field "rule", self.rule.to_s
          json.field "evidence", self.evidence
          json.field "owner_origin", self.owner_origin
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
      def initialize(@rule : DiagnosticHeadRule, @evidence : DiagnosticAnchorEvidence, @head : DiagnosticHead)
        raise ArgumentError.new("invalid head evidence") if @evidence.is_a?(DiagnosticAnchorEvidence::DerivedFromOwner)
      end
      def_equals_and_hash @rule, @evidence, @head
    end
    class PayloadOf < DiagnosticAnchorUse
      getter rule : DiagnosticPayloadRule
      getter evidence : DiagnosticAnchorEvidence
      getter owner_origin : DiagnosticOrigin::Expanded
      def initialize(@rule : DiagnosticPayloadRule, @evidence : DiagnosticAnchorEvidence, @owner_origin : DiagnosticOrigin::Expanded)
        raise ArgumentError.new("invalid payload evidence") if @evidence.is_a?(DiagnosticAnchorEvidence::RawSyntax)
      end
      def_equals_and_hash @rule, @evidence, @owner_origin
    end
  end

  class DiagnosticFragmentBuilder
    @events = [] of DiagnosticTokenEvent
    @anchors = [] of DiagnosticAnchor

    def add_event(event : DiagnosticTokenEvent) : Int32
      @events.each_with_index do |existing, index|
        if existing.selected_start == event.selected_start && existing.selected_end == event.selected_end
          raise ArgumentError.new("conflicting fragment token events") unless existing == event
          return index
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

    def finish(key : String, text : String) : IyiMod::DiagnosticFragment
      raise ArgumentError.new("invalid fragment text") unless text.valid_encoding?
      events_with_index = @events.each_with_index.to_a
      events_with_index.sort_by! do |event, _|
        {event.selected_start, event.selected_end, event.selection.value, event.token_kind, event.token_text, event.lexical_mode}
      end
      event_remap = Array(Int32).new(@events.size, 0)
      events = events_with_index.map_with_index do |(event, old_index), new_index|
        unless event.input_end <= text.bytesize &&
               text.byte_slice(event.input_start, event.input_end - event.input_start) == event.token_text
          raise ArgumentError.new("fragment token bytes do not match text")
        end
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
      IyiMod::DiagnosticFragment.new(key, ::Crystal::Digest::SHA256.hexdigest(text), events, anchors)
    end
  end

  record DiagnosticMacroAnchor, offset : Int32, end_offset : Int32, kind : String, role : String,
    emitter_origin : DiagnosticOrigin?, source_origin : DiagnosticOrigin?, producer : DiagnosticMacroProducer?

  record DiagnosticGeneratedText, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, producer : DiagnosticMacroProducer

  record DiagnosticMacroNameFragment, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, source_name : DiagnosticNameValue

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
        expected_keys(object, %w(kind invocation_origin macro_definition_origin expansion_guard generated_byte_offset generated_byte_end token_kind token_text lexical_mode anchor_kind role name_context emission_parts))
        %w(expansion_guard token_kind token_text lexical_mode anchor_kind role).each { |key| budget.text(object[key].as_s) }
        budget.text(object["name_context"].as_s) unless object["name_context"].raw.nil?
        budget.consume(object["emission_parts"].as_a.size.to_u64 * 1024_u64)
        parts = object["emission_parts"].as_a.map do |part|
          fields = part.as_h
          emitter = fields["emitter_origin"]
          emitter_origin = emitter.raw.nil? ? nil : from_json(emitter, depth + 1, budget)
          start = fields["start_offset"].as_i
          finish = fields["end_offset"].as_i
          case fields["kind"].as_s
          when "Generated"
            expected_keys(fields, %w(kind start_offset end_offset emitter_origin producer))
            budget.text(fields["producer"].as_s)
            DiagnosticEmissionPart::Generated.new(start, finish, emitter_origin, DiagnosticMacroProducer.parse(fields["producer"].as_s)).as(DiagnosticEmissionPart)
          when "AstAnchor"
            expected_keys(fields, %w(kind start_offset end_offset emitter_origin source_origin))
            DiagnosticEmissionPart::AstAnchor.new(start, finish, emitter_origin, from_json(fields["source_origin"], depth + 1, budget)).as(DiagnosticEmissionPart)
          when "NameSplice"
            expected_keys(fields, %w(kind start_offset end_offset emitter_origin source_name))
            DiagnosticEmissionPart::NameSplice.new(start, finish, emitter_origin,
              name_value_from_json(fields["source_name"], depth + 1, budget)).as(DiagnosticEmissionPart)
          else
            raise ArgumentError.new("unknown diagnostic emission part")
          end
        end
        Expanded.new(from_json(object["invocation_origin"], depth + 1, budget),
          from_json(object["macro_definition_origin"], depth + 1, budget),
          object["expansion_guard"].as_s, object["generated_byte_offset"].as_i, object["generated_byte_end"].as_i,
          object["token_kind"].as_s, object["token_text"].as_s, object["lexical_mode"].as_s,
          object["anchor_kind"].as_s, object["role"].as_s, object["name_context"].as_s?, parts)
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
        @producer_context = "path_segment"
        @rendered_text = result.to_s
        @witnesses = witnesses.dup
        production = @production.not_nil!
        expected, allowed_results, allowed_indices = case production
          when DiagnosticTypeSugar::Pointer then {["*"], [DiagnosticTypeSugarResult::Pointer], [0]}
          when DiagnosticTypeSugar::DoublePointer then {["**"], [DiagnosticTypeSugarResult::Pointer], [0, 1]}
          when DiagnosticTypeSugar::NilableType then {["?"], [DiagnosticTypeSugarResult::Nil], [0]}
          when DiagnosticTypeSugar::NilableExpression then {["?"], [DiagnosticTypeSugarResult::Union, DiagnosticTypeSugarResult::Nil], [0]}
          when DiagnosticTypeSugar::SelfNilableType then {["self?"], [DiagnosticTypeSugarResult::Nil], [0]}
          when DiagnosticTypeSugar::StaticArray then {["[", "]"], [DiagnosticTypeSugarResult::StaticArray], [0]}
          when DiagnosticTypeSugar::Tuple then {["{", "}"], [DiagnosticTypeSugarResult::Tuple], [0]}
          when DiagnosticTypeSugar::NamedTuple then {["{", "}"], [DiagnosticTypeSugarResult::NamedTuple], [0]}
          when DiagnosticTypeSugar::NilPredicate then {["nil?"], [DiagnosticTypeSugarResult::Nil], [0]}
          else raise ArgumentError.new("unknown type-sugar production")
        end
        unless @witnesses.map(&.raw_text) == expected && allowed_results.includes?(result) && allowed_indices.includes?(@lowering_index)
          raise ArgumentError.new("invalid type-sugar derivation")
        end
        first = @witnesses.first
        @witnesses.each_cons_pair do |left, right|
          unless left.input_sha256 == right.input_sha256 && left.input_bytesize == right.input_bytesize &&
                 left.lexical_mode == right.lexical_mode && left.input_end <= right.input_start
            raise ArgumentError.new("inconsistent type-sugar witnesses")
          end
        end
        parents = @witnesses.map(&.lexical_origin)
        set_graph_bounds!(1024_u64 + @witnesses.sum { |w| w.raw_text.bytesize.to_u64 * 6 + 256_u64 }, parents)
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
            raise ArgumentError.new("raw syntax witness validation unavailable")
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
          when DiagnosticHead::Syntax
            expected_text = case head.form
                            when DiagnosticHeadSyntax::GlobalPathPrefix then "::"
                            when DiagnosticHeadSyntax::FirstSplat then "*"
                            when DiagnosticHeadSyntax::FirstUnderscore then "_"
                            when DiagnosticHeadSyntax::ParenthesizedFirstTarget then "("
                            else raise ArgumentError.new("invalid syntax head")
                            end
            raise ArgumentError.new("syntax head token mismatch") unless @token_event.selected_text == expected_text
          end
        when DiagnosticAnchorUse::PayloadOf
          owner = use.owner_origin.as(Expanded)
          unless owner.invocation_origin == @invocation_origin && owner.macro_definition_origin == @macro_definition_origin &&
                 owner.expansion_guard == @expansion_guard && owner.token_event == @token_event
            raise ArgumentError.new("payload event mismatch")
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
