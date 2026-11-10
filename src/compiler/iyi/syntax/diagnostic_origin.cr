require "json"

module Iyi
  class DiagnosticAnchor
    getter offset : Int32
    getter kind : String
    getter role : String
    getter origin : DiagnosticOrigin?
    @name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticSourceNameToken))

    def initialize(@offset : Int32, @kind : String, @role : String, @origin : DiagnosticOrigin?,
                   name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticSourceNameToken)) = {} of DiagnosticNameSlot => Array(DiagnosticSourceNameToken))
      @name_slots = DiagnosticNameMetadata.copy_and_validate(name_slots, @origin)
    end

    def name_slots : Hash(DiagnosticNameSlot, Array(DiagnosticSourceNameToken))
      DiagnosticNameMetadata.copy_and_validate(@name_slots, @origin)
    end

    def_equals_and_hash @offset, @kind, @role, @origin, @name_slots
  end

  record DiagnosticRegion,
    start_offset : Int32,
    end_offset : Int32,
    text_sha256 : String,
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

    def self.valid_token?(kind : String, raw : String, mode : String, context : String) : Bool
      allowed = case context
                when "method_name"                   then kind == "IDENT" || kind == "CONST" || NAME_OPERATORS.includes?(kind)
                when "definition_name"               then kind == "IDENT" || NAME_OPERATORS.includes?(kind)
                when "macro_name"                    then kind == "IDENT" || kind == "="
                when "local_reference"               then kind == "IDENT"
                when "instance_variable"             then kind == "INSTANCE_VAR"
                when "class_variable"                then kind == "CLASS_VAR"
                when "parameter"                     then {"IDENT", "INSTANCE_VAR", "CLASS_VAR"}.includes?(kind)
                when "path_segment", "type_parameter" then kind == "CONST"
                when "named_entry"                   then {"IDENT", "CONST"}.includes?(kind)
                else                                      false
                end
      return false unless allowed && {"Crystal", "Iyi"}.includes?(mode) && raw.valid_encoding?
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
              "class_variable", "parameter", "path_segment", "type_parameter", "named_entry"}.includes?(@context)
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
      case @lexical_origin
      when DiagnosticOrigin::Written
        raise ArgumentError.new("name token origin offset mismatch") unless @lexical_origin.input_byte_offset == @input_start
      when DiagnosticOrigin::Expanded
        unless @lexical_origin.generated_byte_offset == @input_start && @lexical_origin.expansion_guard == "sha256:#{@input_sha256}"
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

  module DiagnosticNameMetadata
    def self.copy_and_validate(slots : Hash(DiagnosticNameSlot, Array(DiagnosticSourceNameToken)), origin : DiagnosticOrigin? = nil)
      remaining = DiagnosticOrigin::MAX_UNFOLDED_BYTES
      if origin
        raise ArgumentError.new("diagnostic name metadata exceeds size limit") if origin.graph_bytes > remaining
        remaining -= origin.graph_bytes
      end
      copy = {} of DiagnosticNameSlot => Array(DiagnosticSourceNameToken)
      slots.each do |slot, tokens|
        raise ArgumentError.new("empty diagnostic name slot") if tokens.empty?
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
          json.field "producer", producer.to_s
        when AstAnchor
          json.field "source_origin", source_origin
        when NameSplice
          json.field "source_token", source_token
          json.field "slice_start", slice_start
          json.field "slice_end", slice_end
          json.field "projection", projection
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
      getter source_token : DiagnosticSourceNameToken
      getter slice_start : Int32
      getter slice_end : Int32
      getter projection : String
      def initialize(start_offset : Int32, end_offset : Int32, emitter_origin : DiagnosticOrigin?,
                     @source_token : DiagnosticSourceNameToken, @slice_start : Int32, @slice_end : Int32, @projection : String)
        super(start_offset, end_offset, emitter_origin)
        unless @projection == "Whole" && @slice_start == 0 && @slice_end == @source_token.raw_text.bytesize &&
               @end_offset - @start_offset == @slice_end - @slice_start
          raise ArgumentError.new("unsupported diagnostic name projection")
        end
      end
      def_equals_and_hash @start_offset, @end_offset, @emitter_origin, @source_token, @slice_start, @slice_end, @projection
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

  record DiagnosticMacroAnchor, offset : Int32, kind : String, role : String,
    emitter_origin : DiagnosticOrigin?, source_origin : DiagnosticOrigin?, producer : DiagnosticMacroProducer?

  record DiagnosticGeneratedText, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, producer : DiagnosticMacroProducer

  record DiagnosticMacroNameFragment, start_offset : Int32, end_offset : Int32,
    emitter_origin : DiagnosticOrigin?, source_token : DiagnosticSourceNameToken

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
            expected_keys(fields, %w(kind start_offset end_offset emitter_origin source_token slice_start slice_end projection))
            token = fields["source_token"].as_h
            expected_keys(token, %w(lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
            %w(context input_sha256 lexical_mode token_kind raw_text).each { |key| budget.text(token[key].as_s) }
            budget.text(fields["projection"].as_s)
            binding = token["binding_origin"]
            source = DiagnosticSourceNameToken.new(from_json(token["lexical_origin"], depth + 1, budget),
              binding.raw.nil? ? nil : from_json(binding, depth + 1, budget), token["context"].as_s,
              token["input_sha256"].as_s, token["input_bytesize"].as_i, token["input_start"].as_i,
              token["input_end"].as_i, token["lexical_mode"].as_s, token["token_kind"].as_s, token["raw_text"].as_s)
            DiagnosticEmissionPart::NameSplice.new(start, finish, emitter_origin, source,
              fields["slice_start"].as_i, fields["slice_end"].as_i, fields["projection"].as_s).as(DiagnosticEmissionPart)
          else
            raise ArgumentError.new("unknown diagnostic emission part")
          end
        end
        Expanded.new(from_json(object["invocation_origin"], depth + 1, budget),
          from_json(object["macro_definition_origin"], depth + 1, budget),
          object["expansion_guard"].as_s, object["generated_byte_offset"].as_i, object["generated_byte_end"].as_i,
          object["token_kind"].as_s, object["token_text"].as_s, object["lexical_mode"].as_s,
          object["anchor_kind"].as_s, object["role"].as_s, object["name_context"].as_s?, parts)
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

    private def self.expected_keys(object : Hash(String, JSON::Any), keys : Array(String)) : Nil
      unless object.size == keys.size && keys.all? { |key| object.has_key?(key) }
        raise ArgumentError.new("invalid diagnostic origin fields")
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
      getter generated_byte_offset : Int32
      getter generated_byte_end : Int32
      getter token_kind : String
      getter token_text : String
      getter lexical_mode : String
      getter anchor_kind : String
      getter role : String
      getter name_context : String?
      @emission_parts : Array(DiagnosticEmissionPart)

      def emission_parts : Array(DiagnosticEmissionPart)
        @emission_parts.dup
      end

      def initialize(@invocation_origin : DiagnosticOrigin, @macro_definition_origin : DiagnosticOrigin,
                     @expansion_guard : String, @generated_byte_offset : Int32, @generated_byte_end : Int32,
                     @token_kind : String, @token_text : String, @lexical_mode : String,
                     @anchor_kind : String, @role : String, @name_context : String?,
                     emission_parts : Array(DiagnosticEmissionPart))
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
        unless @generated_byte_offset >= 0 && @generated_byte_end > @generated_byte_offset &&
               @token_text.bytesize == @generated_byte_end - @generated_byte_offset && @token_text.valid_encoding? &&
               !@token_kind.empty? && {"Crystal", "Iyi"}.includes?(@lexical_mode) && !@anchor_kind.empty? && !@role.empty?
          raise ArgumentError.new("invalid diagnostic expansion token")
        end
        if context = @name_context
          unless DiagnosticSourceNameToken.valid_token?(@token_kind, @token_text, @lexical_mode, context)
            raise ArgumentError.new("invalid diagnostic name token")
          end
          unless (@anchor_kind == "Name" && @role == context) ||
                 (@anchor_kind == "Call" && @role == "method" && context == "method_name")
            raise ArgumentError.new("invalid receiving diagnostic name role")
          end
        end
        raise ArgumentError.new("missing macro emission parts") if emission_parts.empty?
        @emission_parts = emission_parts.dup
        cursor = @generated_byte_offset
        parents = [@invocation_origin, @macro_definition_origin] of DiagnosticOrigin
        own = 1024_u64 + DiagnosticOrigin.json_string_size(@token_text) + DiagnosticOrigin.json_string_size(@token_kind) +
              DiagnosticOrigin.json_string_size(@anchor_kind) + DiagnosticOrigin.json_string_size(@role)
        @emission_parts.each do |part|
          raise ArgumentError.new("invalid macro emission coverage") unless part.start_offset == cursor && part.end_offset <= @generated_byte_end
          cursor = part.end_offset
          part.emitter_origin.try { |origin| parents << origin }
          own += 1024_u64
          bytes = @token_text.byte_slice(part.start_offset - @generated_byte_offset, part.end_offset - part.start_offset)
          raise ArgumentError.new("macro emission splits a UTF-8 character") unless bytes.valid_encoding?
          case part
          when DiagnosticEmissionPart::AstAnchor
            unless @emission_parts.size == 1 && part.source_origin.valid_for_anchor?(@anchor_kind, @role)
              raise ArgumentError.new("invalid structural macro splice")
            end
            parents << part.source_origin
          when DiagnosticEmissionPart::NameSplice
            raise ArgumentError.new("name splice without name context") unless @name_context
            token = part.source_token
            parents << token.lexical_origin
            token.binding_origin.try { |binding| parents << binding }
            own += DiagnosticOrigin.json_string_size(token.raw_text) + DiagnosticOrigin.json_string_size(token.input_sha256) +
                   DiagnosticOrigin.json_string_size(token.token_kind) + DiagnosticOrigin.json_string_size(token.context)
            bytes = @token_text.byte_slice(part.start_offset - @generated_byte_offset, part.end_offset - part.start_offset)
            unless bytes == token.raw_text.byte_slice(part.slice_start, part.slice_end - part.slice_start)
              raise ArgumentError.new("name splice bytes differ from source")
            end
          end
          raise ArgumentError.new("diagnostic origin graph exceeds size limit") if own > MAX_UNFOLDED_BYTES
        end
        raise ArgumentError.new("incomplete macro emission coverage") unless cursor == @generated_byte_end
        set_graph_bounds!(own, parents)
        @emission_parts.each_cons_pair do |left, right|
          if left.is_a?(DiagnosticEmissionPart::Generated) && right.is_a?(DiagnosticEmissionPart::Generated) &&
             left.producer == right.producer && left.emitter_origin == right.emitter_origin
            raise ArgumentError.new("uncoalesced macro emission parts")
          end
        end
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        @anchor_kind == kind && @role == role
      end

      def_equals_and_hash @invocation_origin, @macro_definition_origin, @expansion_guard, @generated_byte_offset,
        @generated_byte_end, @token_kind, @token_text, @lexical_mode, @anchor_kind, @role, @name_context, @emission_parts

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Expanded"
          json.field "invocation_origin", @invocation_origin
          json.field "macro_definition_origin", @macro_definition_origin
          json.field "expansion_guard", @expansion_guard
          json.field "generated_byte_offset", @generated_byte_offset
          json.field "generated_byte_end", @generated_byte_end
          json.field "token_kind", @token_kind
          json.field "token_text", @token_text
          json.field "lexical_mode", @lexical_mode
          json.field "anchor_kind", @anchor_kind
          json.field "role", @role
          json.field "name_context", @name_context
          json.field "emission_parts" do
            json.array do
              @emission_parts.each { |part| part.to_json(json) }
            end
          end
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
