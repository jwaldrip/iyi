require "json"

module Iyi
  record DiagnosticAnchor,
    offset : Int32,
    kind : String,
    role : String,
    origin : DiagnosticOrigin?

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

  record DiagnosticEmissionPart, start_offset : Int32, end_offset : Int32, emitter_origin : DiagnosticOrigin?

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
  # Provenance is independent of Location, which remains the source of
  # human-facing positions. These records contain no process-local identity.
  abstract class DiagnosticOrigin
    abstract def to_json(json : JSON::Builder) : Nil
    abstract def valid_for_anchor?(kind : String, role : String) : Bool
    MAX_DEPTH = 128
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
                else                                                1_u64
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
             when Expanded  then invocation_origin.written_invocation_root
             when Synthetic then parent_origin.written_invocation_root
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
      when Expanded  then invocation_origin.written_invocation_root
      when Synthetic then parent_origin.written_invocation_root
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
        expected_keys(object, %w(kind invocation_origin macro_definition_origin expansion_guard generated_byte_offset anchor_kind role emission_parts spliced_origin))
        splice = object["spliced_origin"]
        budget.text(object["expansion_guard"].as_s)
        budget.text(object["anchor_kind"].as_s)
        budget.text(object["role"].as_s)
        budget.consume(object["emission_parts"].as_a.size.to_u64)
        parts = object["emission_parts"].as_a.map do |part|
          fields = part.as_h
          expected_keys(fields, %w(start_offset end_offset emitter_origin))
          emitter = fields["emitter_origin"]
          DiagnosticEmissionPart.new(fields["start_offset"].as_i, fields["end_offset"].as_i,
            emitter.raw.nil? ? nil : from_json(emitter, depth + 1, budget))
        end
        Expanded.new(from_json(object["invocation_origin"], depth + 1, budget),
          from_json(object["macro_definition_origin"], depth + 1, budget),
          object["expansion_guard"].as_s, object["generated_byte_offset"].as_i,
          object["anchor_kind"].as_s, object["role"].as_s, parts,
          splice.raw.nil? ? nil : from_json(splice, depth + 1, budget))
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
      getter anchor_kind : String
      getter role : String
      getter spliced_origin : DiagnosticOrigin?
      @emission_parts : Array(DiagnosticEmissionPart)

      def emission_parts : Array(DiagnosticEmissionPart)
        @emission_parts.dup
      end

      def initialize(@invocation_origin : DiagnosticOrigin, @macro_definition_origin : DiagnosticOrigin,
                     expansion_guard : String, generated_byte_offset : Int32,
                     anchor_kind : String, role : String, emission_parts : Array(DiagnosticEmissionPart),
                     @spliced_origin : DiagnosticOrigin? = nil)
        parents = [@invocation_origin, @macro_definition_origin] of DiagnosticOrigin
        @spliced_origin.try { |origin| parents << origin }
        emission_parts.each { |part| part.emitter_origin.try { |origin| parents << origin } }
        own = %({"kind":"Expanded","invocation_origin":,"macro_definition_origin":,"expansion_guard":,"generated_byte_offset":,"anchor_kind":,"role":,"emission_parts":[],"spliced_origin":}).bytesize.to_u64
        own += DiagnosticOrigin.json_string_size(expansion_guard) + generated_byte_offset.to_s.bytesize.to_u64
        own += DiagnosticOrigin.json_string_size(anchor_kind) + DiagnosticOrigin.json_string_size(role)
        own += 4_u64 unless @spliced_origin
        emission_parts.each_with_index do |part, index|
          own += 1_u64 if index > 0
          own += %({"start_offset":,"end_offset":,"emitter_origin":}).bytesize.to_u64
          own += part.start_offset.to_s.bytesize.to_u64 + part.end_offset.to_s.bytesize.to_u64
          own += 4_u64 unless part.emitter_origin
        end
        set_graph_bounds!(own, parents)
        invocation_valid = @invocation_origin.valid_for_anchor?("Call", "method") ||
                           @invocation_origin.valid_for_anchor?("MacroDirective", "control") ||
                           @invocation_origin.valid_for_anchor?("MacroDirective", "expression")
        unless invocation_valid && @macro_definition_origin.valid_for_anchor?("Macro", "keyword")
          raise ArgumentError.new("unsupported diagnostic macro invocation or definition origin")
        end
        @expansion_guard = DiagnosticOrigin.require_text(expansion_guard, "expansion guard")
        unless @expansion_guard.starts_with?("sha256:") && @expansion_guard.bytesize == 71 &&
               @expansion_guard.byte_slice(7, 64).each_byte.all? { |byte| (byte >= 48_u8 && byte <= 57_u8) || (byte >= 97_u8 && byte <= 102_u8) }
          raise ArgumentError.new("invalid diagnostic expansion guard")
        end
        @generated_byte_offset = DiagnosticOrigin.require_offset(generated_byte_offset, "generated offset")
        @anchor_kind = DiagnosticOrigin.require_text(anchor_kind, "anchor kind")
        @role = DiagnosticOrigin.require_text(role, "role")
        raise ArgumentError.new("missing macro emission parts") if emission_parts.empty?
        @emission_parts = emission_parts.dup
        cursor = @generated_byte_offset
        previous_emitter = nil.as(DiagnosticOrigin?)
        @emission_parts.each_with_index do |part, index|
          unless part.start_offset == cursor && part.end_offset > part.start_offset
            raise ArgumentError.new("invalid macro emission part extent")
          end
          emitter = part.emitter_origin
          if emitter && !emitter.valid_for_anchor?("MacroDirective", "expression") &&
             !emitter.valid_for_anchor?("MacroDirective", "control")
            raise ArgumentError.new("invalid macro emission directive")
          end
          raise ArgumentError.new("uncoalesced macro emission parts") if index > 0 && emitter == previous_emitter
          previous_emitter = emitter
          cursor = part.end_offset
        end
        if (spliced = @spliced_origin) && !spliced.valid_for_anchor?(@anchor_kind, @role)
          raise ArgumentError.new("spliced diagnostic origin does not match its anchor")
        end
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        @anchor_kind == kind && @role == role
      end

      def_equals_and_hash @invocation_origin, @macro_definition_origin, @expansion_guard, @generated_byte_offset,
        @anchor_kind, @role, @emission_parts, @spliced_origin

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Expanded"
          json.field "invocation_origin", @invocation_origin
          json.field "macro_definition_origin", @macro_definition_origin
          json.field "expansion_guard", @expansion_guard
          json.field "generated_byte_offset", @generated_byte_offset
          json.field "anchor_kind", @anchor_kind
          json.field "role", @role
          json.field "emission_parts" do
            json.array do
              @emission_parts.each do |part|
                json.object do
                  json.field "start_offset", part.start_offset
                  json.field "end_offset", part.end_offset
                  json.field "emitter_origin", part.emitter_origin
                end
              end
            end
          end
          json.field "spliced_origin", @spliced_origin
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
