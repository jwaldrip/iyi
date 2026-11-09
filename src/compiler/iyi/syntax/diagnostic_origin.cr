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

  # Provenance is independent of Location, which remains the source of
  # human-facing positions. These records contain no process-local identity.
  abstract class DiagnosticOrigin
    abstract def to_json(json : JSON::Builder) : Nil
    abstract def valid_for_anchor?(kind : String, role : String) : Bool

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

    # The artifact reader must reject a partial or extended record rather than
    # treating it as an equivalent origin.
    def self.from_json(value : JSON::Any, depth : Int32 = 0) : DiagnosticOrigin
      raise ArgumentError.new("diagnostic origin nesting is too deep") if depth > 128
      object = value.as_h
      kind = object["kind"].as_s
      case kind
      when "Written"
        expected_keys(object, %w(kind source_identity input_byte_offset anchor_kind role))
        source = object["source_identity"].as_h
        expected_keys(source, %w(module file))
        Written.new(source["module"].as_s, source["file"].as_s,
          object["input_byte_offset"].as_i, object["anchor_kind"].as_s, object["role"].as_s)
      when "Expanded"
        expected_keys(object, %w(kind invocation_origin macro_definition_origin expansion_guard generated_byte_offset anchor_kind role spliced_origin))
        splice = object["spliced_origin"]
        Expanded.new(from_json(object["invocation_origin"], depth + 1),
          from_json(object["macro_definition_origin"], depth + 1),
          object["expansion_guard"].as_s, object["generated_byte_offset"].as_i,
          object["anchor_kind"].as_s, object["role"].as_s,
          splice.raw.nil? ? nil : from_json(splice, depth + 1))
      when "Synthetic"
        expected_keys(object, %w(kind parent_origin synthesis_kind structural_slot))
        Synthetic.new(from_json(object["parent_origin"], depth + 1),
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

      def initialize(@invocation_origin : DiagnosticOrigin, @macro_definition_origin : DiagnosticOrigin,
                     expansion_guard : String, generated_byte_offset : Int32,
                     anchor_kind : String, role : String, @spliced_origin : DiagnosticOrigin? = nil)
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
        if (spliced = @spliced_origin) && !spliced.valid_for_anchor?(@anchor_kind, @role)
          raise ArgumentError.new("spliced diagnostic origin does not match its anchor")
        end
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
        @anchor_kind == kind && @role == role
      end

      def_equals_and_hash @invocation_origin, @macro_definition_origin, @expansion_guard, @generated_byte_offset, @anchor_kind, @role, @spliced_origin

      def to_json(json : JSON::Builder) : Nil
        json.object do
          json.field "kind", "Expanded"
          json.field "invocation_origin", @invocation_origin
          json.field "macro_definition_origin", @macro_definition_origin
          json.field "expansion_guard", @expansion_guard
          json.field "generated_byte_offset", @generated_byte_offset
          json.field "anchor_kind", @anchor_kind
          json.field "role", @role
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
      end

      def valid_for_anchor?(kind : String, role : String) : Bool
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
