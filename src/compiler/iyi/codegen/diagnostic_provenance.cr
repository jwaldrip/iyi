require "json"
require "base64"
require "set"
require "crystal/digest/sha256"
require "../syntax/diagnostic_origin"
require "../syntax/token"

module Iyi::DiagnosticProvenance
  struct Emission
    include JSON::Serializable

    getter requested_symbol : String
    getter actual_llvm_symbol : String
    getter unit_name : String
    getter linkage : String
    getter origin : JSON::Any
    getter specialization : JSON::Any
    getter capture_descriptor : JSON::Any
    getter displayed_source_location : JSON::Any

    def initialize(@requested_symbol, @actual_llvm_symbol, @unit_name, @linkage,
                   @origin, @specialization, @capture_descriptor, @displayed_source_location)
    end
  end

  # Object-local definition; final link-input IDs are deliberately not
  # persisted in artifact records.
  struct Definition
    include JSON::Serializable

    getter emission : Emission
    getter post_partition_llvm_symbol : String
    getter native_object_symbol : String
    getter post_partition_linkage : String
    getter partition_role : String

    def initialize(@emission, @post_partition_llvm_symbol, @native_object_symbol,
                   @post_partition_linkage, @partition_role)
    end
  end

  struct Binding
    include JSON::Serializable

    getter link_input_id : Int32
    getter definition : Definition

    def initialize(@link_input_id, @definition)
    end
  end

  enum NativeKind
    Object
    Executable
  end

  struct NativeSection
    include JSON::Serializable
    getter index : Int32
    getter segment_name_base64 : String
    getter section_name_base64 : String
    getter address : String
    getter size : String
    getter file_offset : UInt32
    getter flags : UInt32

    def initialize(@index, @segment_name_base64, @section_name_base64, @address, @size, @file_offset, @flags)
    end
  end

  struct NativeSymbol
    include JSON::Serializable
    getter index : Int32
    getter string_index : UInt32
    getter name_base64 : String
    getter type : UInt8
    getter section : UInt8
    getter desc : UInt16
    getter value : String

    def initialize(@index, @string_index, @name_base64, @type, @section, @desc, @value)
    end

    def name : String
      String.new(Base64.decode(@name_base64))
    end
  end

  struct NativeEvidence
    include JSON::Serializable
    getter format : String
    getter cpu_type : UInt32
    getter cpu_subtype : UInt32
    getter file_type : UInt32
    getter sections : Array(NativeSection)
    getter symbols : Array(NativeSymbol)

    def initialize(@cpu_type, @cpu_subtype, @file_type, @sections, @symbols)
      @format = "macho64-le-symtab-v1"
    end

    def direct_code?(symbol : NativeSymbol) : Bool
      return false unless symbol.type & 0xe0 == 0 && symbol.type & 0x0e == 0x0e
      section = @sections[symbol.section.to_i - 1]? || return false
      return false unless section.flags & 0xff == 0 && section.flags & 0x02000000 == 0
      return false if section.flags & 0x80000400 == 0
      start = section.address.to_u64(16)
      value = symbol.value.to_u64(16)
      value >= start && value - start < section.size.to_u64(16)
    end

    def direct_named(name : String) : Array(NativeSymbol)
      encoded = Base64.strict_encode(name)
      @symbols.select { |symbol| symbol.name_base64 == encoded && direct_code?(symbol) }
    end
  end

  struct ObjectInput
    include JSON::Serializable

    getter link_input_id : Int32
    getter producer : JSON::Any
    getter unit_name : String
    getter partition : JSON::Any
    getter sha256 : String
    getter bytes_base64 : String
    getter native_evidence : NativeEvidence

    def initialize(@link_input_id, @producer, @unit_name, @partition, @sha256, @bytes_base64, @native_evidence)
    end
  end

  private def self.fields(value : JSON::Any, keys : Array(String)) : Hash(String, JSON::Any)
    object = value.as_h
    raise "invalid diagnostic identity fields" unless object.size == keys.size && keys.all? { |key| object.has_key?(key) }
    object
  end

  private def self.text(value : JSON::Any) : Nil
    raise "empty diagnostic identity text" if value.as_s.empty?
  end

  # Bound the entire unfolded value iteratively before any recursive origin
  # traversal, hashing, or equality. Six bytes per string byte is a safe JSON
  # escape upper bound; fixed per-value charges cover keys and punctuation.
  private def self.bound_origin!(value : JSON::Any) : Nil
    remaining = 8_i64 * 1024 * 1024
    pending = [value]
    until pending.empty?
      item = pending.pop
      remaining -= 32
      case raw = item.raw
      when String
        remaining -= raw.bytesize.to_i64 * 6
      when Array
        remaining -= raw.size.to_i64 * 32
        raise "diagnostic origin exceeds size limit" if remaining < 0
        raw.each { |child| pending << child }
      when Hash
        remaining -= raw.size.to_i64 * 32
        raw.each do |key, child|
          remaining -= key.bytesize.to_i64 * 6
          raise "diagnostic origin exceeds size limit" if remaining < 0
          pending << child
        end
      end
      raise "diagnostic origin exceeds size limit" if remaining < 0
    end
  end

  NAME_CONTEXTS = %w(method_name definition_name macro_name local_reference instance_variable class_variable parameter path_segment type_parameter named_entry)
  MACRO_PRODUCERS = %w(ConstructedAst EmptyTupleProjection EmptyNamedTupleProjection MacroTemplate MacroId MacroVar MacroVerbatim YieldWrapper SemanticPrinter)
  NAME_OPERATORS = %w(! != !~ % & &* &** &+ &- * ** + - / // < << <= <=> = == === =~ > >= >> [] []= []? ^ ` | ~)

  private def self.name_token?(kind : String, raw : String, mode : String, context : String) : Bool
    allowed = case context
              when "method_name"
                kind == "IDENT" || kind == "CONST" || NAME_OPERATORS.includes?(kind)
              when "definition_name"
                kind == "IDENT" || NAME_OPERATORS.includes?(kind)
              when "macro_name", "local_reference"
                kind == "IDENT"
              when "instance_variable"
                kind == "INSTANCE_VAR"
              when "class_variable"
                kind == "CLASS_VAR"
              when "parameter"
                kind == "IDENT" || kind == "INSTANCE_VAR" || kind == "CLASS_VAR"
              when "path_segment", "type_parameter"
                kind == "CONST"
              when "named_entry"
                kind == "IDENT" || kind == "CONST"
              else
                false
              end
    return false unless allowed
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
      initial = char.ascii_letter? || char == '_' || char.ord > 0x9f
      return false unless initial || (index > 0 && char.ascii_number?)
    end
    true
  end


  private def self.origin_schema4!(value : JSON::Any, depth : Int32 = 0) : Nil
    raise "diagnostic origin nesting too deep" if depth > 128
    object = value.as_h
    case object["kind"].as_s
    when "Written"
      written = fields(value, %w(kind source_identity input_byte_offset anchor_kind role))
      fields(written["source_identity"], %w(module file))
    when "Synthetic"
      synthetic = fields(value, %w(kind parent_origin synthesis_kind structural_slot))
      origin_schema4!(synthetic["parent_origin"], depth + 1)
    when "Expanded"
      expansion = fields(value, %w(kind invocation_origin macro_definition_origin expansion_guard generated_byte_offset generated_byte_end token_kind token_text lexical_mode anchor_kind role name_context emission_parts))
      origin_schema4!(expansion["invocation_origin"], depth + 1)
      origin_schema4!(expansion["macro_definition_origin"], depth + 1)
      guard = expansion["expansion_guard"].as_s
      raise "invalid expansion guard" unless guard.matches?(/\Asha256:[0-9a-f]{64}\z/)
      mode = expansion["lexical_mode"].as_s
      raise "invalid lexical mode" unless mode == "Crystal" || mode == "Iyi"
      raise "unknown token kind" unless Iyi::Token::Kind.values.any? { |kind| kind.to_s == expansion["token_kind"].as_s }
      token = expansion["token_text"].as_s
      raise "invalid token text" if token.empty? || !token.valid_encoding?
      first = expansion["generated_byte_offset"].as_i64
      last = expansion["generated_byte_end"].as_i64
      raise "invalid token extent" unless first >= 0 && last <= Int32::MAX && last - first == token.bytesize && last > first
      context = expansion["name_context"]
      raise "missing name context" if expansion["anchor_kind"].as_s == "Name" && context.raw.nil?
      unless context.raw.nil?
        name = context.as_s
        raise "unknown name context" unless NAME_CONTEXTS.includes?(name)
        kind, role = expansion["anchor_kind"].as_s, expansion["role"].as_s
        raise "invalid receiving name role" unless (kind == "Name" && role == name) || (kind == "Call" && role == "method")
        raise "invalid receiving name token" unless name_token?(expansion["token_kind"].as_s, token, mode, name)
      end
      parts = expansion["emission_parts"].as_a
      raise "expanded origin has no emission parts" if parts.empty?
      cursor = first
      parts.each do |part|
        entry = part.as_h
        case entry["kind"].as_s
        when "Generated"
          fields(part, %w(kind start_offset end_offset emitter_origin producer))
          raise "unknown macro producer" unless MACRO_PRODUCERS.includes?(entry["producer"].as_s)
        when "AstAnchor"
          fields(part, %w(kind start_offset end_offset emitter_origin source_origin))
          raise "structural source must cover token" unless parts.size == 1
          origin_schema4!(entry["source_origin"], depth + 1)
          source = Iyi::DiagnosticOrigin.from_json(entry["source_origin"])
          raise "structural source role mismatch" unless source.valid_for_anchor?(expansion["anchor_kind"].as_s, expansion["role"].as_s)
        when "NameSplice"
          fields(part, %w(kind start_offset end_offset emitter_origin source_token slice_start slice_end projection))
          raise "name contribution without context" if context.raw.nil?
          source_name_schema4!(entry["source_token"], depth + 1)
          source = entry["source_token"].as_h
          raw = source["raw_text"].as_s
          lo, hi = entry["slice_start"].as_i64, entry["slice_end"].as_i64
          raise "unsupported name projection" unless entry["projection"].as_s == "Whole" && lo == 0 && hi == raw.bytesize
          offset = entry["start_offset"].as_i64 - first
          length = entry["end_offset"].as_i64 - entry["start_offset"].as_i64
          raise "invalid name contribution" unless offset >= 0 && length == hi && offset + length <= token.bytesize
          raise "name contribution differs" unless token.byte_slice(offset.to_i, length.to_i) == raw
        else
          raise "unknown emission part"
        end
        start_offset = entry["start_offset"].as_i64
        end_offset = entry["end_offset"].as_i64
        raise "invalid origin emission part range" unless start_offset == cursor && end_offset > cursor && end_offset <= last
        raise "emission splits UTF-8" unless token.byte_slice((start_offset - first).to_i, (end_offset - start_offset).to_i).valid_encoding?
        emitter = entry["emitter_origin"]
        unless emitter.raw.nil?
          origin_schema4!(emitter, depth + 1)
          directive = Iyi::DiagnosticOrigin.from_json(emitter)
          raise "invalid emitter" unless directive.valid_for_anchor?("MacroDirective", "control") || directive.valid_for_anchor?("MacroDirective", "expression")
        end
        cursor = end_offset
      end
      raise "incomplete token coverage" unless cursor == last
    else
      raise "unknown diagnostic origin kind"
    end
  end

  private def self.source_name_schema4!(value : JSON::Any, depth : Int32) : Nil
    source = fields(value, %w(lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
    context = source["context"].as_s
    raise "unknown source name context" unless NAME_CONTEXTS.includes?(context)
    lexical = source["lexical_origin"]
    origin_schema4!(lexical, depth)
    origin = Iyi::DiagnosticOrigin.from_json(lexical)
    raise "invalid source name role" unless origin.valid_for_anchor?("Call", "method") || origin.valid_for_anchor?("Name", context)
    binding = source["binding_origin"]
    unless binding.raw.nil?
      origin_schema4!(binding, depth)
      b = fields(binding, %w(kind parent_origin synthesis_kind structural_slot))
      raise "invalid source binding" unless b["kind"].as_s == "Synthetic" && b["synthesis_kind"].as_s == "local_binding" && b["structural_slot"].as_s == "assignment" && b["parent_origin"] == lexical && origin.valid_for_anchor?("Call", "method")
    end
    digest = source["input_sha256"].as_s
    raise "invalid source input digest" unless digest.matches?(/\A[0-9a-f]{64}\z/)
    mode = source["lexical_mode"].as_s
    raise "invalid lexical mode" unless mode == "Crystal" || mode == "Iyi"
    raise "unknown token kind" unless Iyi::Token::Kind.values.any? { |kind| kind.to_s == source["token_kind"].as_s }
    raw = source["raw_text"].as_s
    raise "invalid source token text" if raw.empty? || !raw.valid_encoding?
    raise "invalid source name token" unless name_token?(source["token_kind"].as_s, raw, mode, context)
    size, first, last = source["input_bytesize"].as_i64, source["input_start"].as_i64, source["input_end"].as_i64
    raise "invalid source token span" unless first >= 0 && last > first && last <= size && size <= Int32::MAX && last - first == raw.bytesize
    case lexical.as_h["kind"].as_s
    when "Written"
      raise "source offset mismatch" unless lexical.as_h["input_byte_offset"].as_i64 == first
    when "Expanded"
      expanded = lexical.as_h
      raise "expanded source mismatch" unless expanded["generated_byte_offset"].as_i64 == first && expanded["generated_byte_end"].as_i64 == last && expanded["expansion_guard"].as_s == "sha256:#{digest}" && expanded["token_text"].as_s == raw
    else
      raise "invalid source lexical origin"
    end
  end

  private def self.validated_origin(value : JSON::Any) : Iyi::DiagnosticOrigin
    bound_origin!(value)
    origin_schema4!(value)
    Iyi::DiagnosticOrigin.from_json(value)
  end

  private def self.type_identity(value : JSON::Any, depth : Int32) : Nil
    raise "diagnostic identity nesting too deep" if depth > 128
    object = value.as_h
    kind = object["kind"].as_s
    case kind
    when "Iyi::Program"
      fields(value, %w(kind))
    when "Iyi::NilType", "Iyi::VoidType", "Iyi::BoolType", "Iyi::CharType",
         "Iyi::IntegerType", "Iyi::FloatType", "Iyi::SymbolType", "Iyi::NoReturnType",
         "Iyi::PrimitiveType", "Iyi::AliasType", "Iyi::ClassType", "Iyi::ModuleType", "Iyi::EnumType",
         "Iyi::NonGenericClassType", "Iyi::NonGenericModuleType", "Iyi::TraitType", "Iyi::FileModule",
         "Iyi::GenericClassType", "Iyi::GenericModuleType", "Iyi::GenericTraitType", "Iyi::LibType"
      text(fields(value, %w(kind name))["name"])
    when "Iyi::UnionType", "Iyi::NilableType", "Iyi::NilableReferenceUnionType",
         "Iyi::ReferenceUnionType", "Iyi::NilableProcType", "Iyi::MixedUnionType"
      fields(value, %w(kind members))["members"].as_a.each { |item| type_identity(item, depth + 1) }
    when "Iyi::VirtualType"
      type_identity(fields(value, %w(kind base))["base"], depth + 1)
    when "Iyi::MetaclassType", "Iyi::VirtualMetaclassType", "Iyi::GenericClassInstanceMetaclassType", "Iyi::GenericModuleInstanceMetaclassType"
      type_identity(fields(value, %w(kind instance))["instance"], depth + 1)
    when "Iyi::TupleInstanceType"
      fields(value, %w(kind elements))["elements"].as_a.each { |item| type_identity(item, depth + 1) }
    when "Iyi::NamedTupleInstanceType"
      fields(value, %w(kind entries))["entries"].as_a.each do |item|
        entry = fields(item, %w(name type))
        text(entry["name"])
        type_identity(entry["type"], depth + 1)
      end
    when "Iyi::ProcInstanceType"
      proc = fields(value, %w(kind arguments return))
      proc["arguments"].as_a.each { |item| type_identity(item, depth + 1) }
      type_identity(proc["return"], depth + 1)
    when "Iyi::StaticArrayInstanceType"
      array = fields(value, %w(kind element size_kind size_value))
      type_identity(array["element"], depth + 1)
      text(array["size_kind"])
      text(array["size_value"])
    when "Iyi::PointerInstanceType"
      type_identity(fields(value, %w(kind element))["element"], depth + 1)
    when "Iyi::GenericClassInstanceType", "Iyi::GenericModuleInstanceType"
      generic = fields(value, %w(kind owner parameters))
      text(generic["owner"])
      generic["parameters"].as_a.each do |item|
        entry = fields(item, %w(name type))
        text(entry["name"])
        type_identity(entry["type"], depth + 1)
      end
    when "Iyi::TypeDefType"
      typedef = fields(value, %w(kind name target))
      text(typedef["name"])
      type_identity(typedef["target"], depth + 1)
    else
      raise "unknown diagnostic type kind #{kind}"
    end
  end

  private def self.optional_type(value : JSON::Any, depth : Int32) : Nil
    type_identity(value, depth + 1) unless value.raw.nil?
  end

  private def self.scope_identity(value : JSON::Any, depth : Int32, current_kind : String = "") : Nil
    raise "diagnostic identity nesting too deep" if depth > 128
    case value.as_h["kind"].as_s
    when "program"
      fields(value, %w(kind))
    when "current_scope"
      raise "unexpected current lexical scope" unless value.as_h["kind"].as_s == current_kind
      fields(value, %w(kind))
    when "def", "block"
      scope = fields(value, %w(kind origin specialization))
      validated_origin(scope["origin"])
      if scope["kind"].as_s == "def"
        specialization_identity(scope["specialization"], depth + 1)
      else
        block_identity(scope["specialization"], depth + 1)
      end
    else
      raise "unknown diagnostic binding scope"
    end
  end

  private def self.binding_identity(value : JSON::Any, depth : Int32, current_kind : String) : Nil
    keys = current_kind.empty? ? %w(name binding_origin scope type mutable) : %w(name binding_origin scope type mutable closured assigned)
    binding = fields(value, keys)
    text(binding["name"])
    origin = validated_origin(binding["binding_origin"])
    raise "invalid diagnostic binding origin" unless origin.valid_for_binding?
    scope_identity(binding["scope"], depth + 1, current_kind)
    type_identity(binding["type"], depth + 1)
    binding["mutable"].as_bool
    unless current_kind.empty?
      binding["closured"].as_bool
      binding["assigned"].as_bool
    end
  end

  private def self.block_identity(value : JSON::Any, depth : Int32) : Nil
    raise "diagnostic identity nesting too deep" if depth > 128
    block = fields(value, %w(origin parameter_types return_type enclosing_specialization environment))
    validated_origin(block["origin"])
    block["parameter_types"].as_a.each { |item| type_identity(item, depth + 1) }
    type_identity(block["return_type"], depth + 1)
    unless block["enclosing_specialization"].raw.nil?
      specialization_identity(block["enclosing_specialization"], depth + 1)
    end
    environment = fields(block["environment"], %w(self_type lexical_scope_type bindings))
    optional_type(environment["self_type"], depth + 1)
    optional_type(environment["lexical_scope_type"], depth + 1)
    environment["bindings"].as_a.each { |item| binding_identity(item, depth + 1, "current_scope") }
  end

  private def self.specialization_identity(value : JSON::Any, depth : Int32 = 0) : Nil
    raise "diagnostic identity nesting too deep" if depth > 128
    object = value.as_h
    if object["kind"]?.try(&.as_s?) == "program_scope"
      scope = fields(value, %w(kind source_identity))
      source = fields(scope["source_identity"], %w(module file))
      text(source["module"])
      text(source["file"])
      return
    end
    if object["kind"]?.try(&.as_s?) == "proc_scope"
      scope = fields(value, %w(kind origin proc_type enclosing_specialization environment))
      validated_origin(scope["origin"])
      raise "proc scope type is not a Proc" unless scope["proc_type"].as_h["kind"].as_s == "Iyi::ProcInstanceType"
      type_identity(scope["proc_type"], depth + 1)
      specialization_identity(scope["enclosing_specialization"], depth + 1)
      environment = fields(scope["environment"], %w(self_type lexical_scope_type bindings))
      optional_type(environment["self_type"], depth + 1)
      optional_type(environment["lexical_scope_type"], depth + 1)
      environment["bindings"].as_a.each { |item| binding_identity(item, depth + 1, "current_scope") }
      return
    end
    spec = fields(value, %w(definition_origin dispatch_type defining_owner ordered_argument_types block_parameter_type named_argument_types free_variable_bindings expansion_shape lexical_block_specialization))
    validated_origin(spec["definition_origin"])
    type_identity(spec["dispatch_type"], depth + 1)
    type_identity(spec["defining_owner"], depth + 1)
    spec["ordered_argument_types"].as_a.each { |item| type_identity(item, depth + 1) }
    optional_type(spec["block_parameter_type"], depth + 1)
    {"named_argument_types", "free_variable_bindings"}.each do |key|
      spec[key].as_a.each do |item|
        entry = fields(item, %w(name type))
        text(entry["name"])
        type_identity(entry["type"], depth + 1)
      end
    end
    shape = fields(spec["expansion_shape"], %w(positional_count splat_index double_splat_name formal_parameters))
    raise "negative positional argument count" if shape["positional_count"].as_i64 < 0
    shape["splat_index"].as_i64 unless shape["splat_index"].raw.nil?
    text(shape["double_splat_name"]) unless shape["double_splat_name"].raw.nil?
    shape["formal_parameters"].as_a.each do |item|
      formal = fields(item, %w(name external_name has_default))
      text(formal["name"])
      text(formal["external_name"])
      formal["has_default"].as_bool
    end
    block_identity(spec["lexical_block_specialization"], depth + 1) unless spec["lexical_block_specialization"].raw.nil?
  end

  private def self.environment_identity(value : JSON::Any, depth : Int32) : Nil
    raise "diagnostic identity nesting too deep" if depth > 128
    environment = fields(value, %w(captured_self_type bindings parent))
    optional_type(environment["captured_self_type"], depth + 1)
    environment["bindings"].as_a.each { |item| binding_identity(item, depth + 1, "") }
    environment_identity(environment["parent"], depth + 1) unless environment["parent"].raw.nil?
  end

  def self.validate_emission!(record : Emission) : Nil
    if record.requested_symbol.empty? || record.actual_llvm_symbol.empty? || record.unit_name.empty? || record.linkage.empty?
      raise "frame provenance contains an incomplete emission"
    end
    origin = validated_origin(record.origin)
    raise "emission origin is not a proc literal" unless origin.valid_for_anchor?("ProcLiteral", "arrow")
    specialization_identity(record.specialization)
    capture = fields(record.capture_descriptor, %w(proc_type is_closure environment))
    raise "frame provenance type is not a Proc" unless capture["proc_type"].as_h["kind"].as_s == "Iyi::ProcInstanceType"
    type_identity(capture["proc_type"], 0)
    is_closure = capture["is_closure"].as_bool
    if is_closure
      environment_identity(capture["environment"], 0)
    elsif !capture["environment"].raw.nil?
      raise "non-closure has a capture environment"
    end
    location = fields(record.displayed_source_location, %w(file line column))
    text(location["file"])
    raise "invalid displayed source location" unless location["line"].as_i64 > 0 && location["column"].as_i64 > 0
  end

  def self.validate_definition!(definition : Definition) : Nil
    validate_emission!(definition.emission)
    if definition.post_partition_llvm_symbol.empty? || definition.native_object_symbol.empty? ||
       definition.post_partition_linkage.empty? || !definition.partition_role.in?("single", "owner", "local_copy")
      raise "invalid diagnostic object definition"
    end
  end

  private class MachReader
    def initialize(@bytes : Bytes)
    end

    def span(offset : UInt64, size : UInt64) : Bytes
      raise "truncated Mach-O" if offset > @bytes.size || size > @bytes.size.to_u64 - offset
      @bytes[offset.to_i, size.to_i]
    end

    def number(offset : UInt64, size : Int32) : UInt64
      result = 0_u64
      span(offset, size.to_u64).each_with_index { |byte, i| result |= byte.to_u64 << (8 * i) }
      result
    end

    def u32(offset : UInt64) : UInt32
      number(offset, 4).to_u32
    end

    def u64(offset : UInt64) : UInt64
      number(offset, 8)
    end
  end

  private def self.hex64(value : UInt64) : String
    value.to_s(16).rjust(16, '0')
  end

  def self.target_cpu(triple : String) : UInt32
    arch = triple.split('-').first
    case arch
    when "arm64", "aarch64" then 0x0100000c_u32
    when "x86_64"           then 0x01000007_u32
    else                         raise "unsupported frame provenance target architecture: #{arch}"
    end
  end

  def self.parse_native_evidence(bytes : Bytes, expected_kind : NativeKind) : NativeEvidence
    r = MachReader.new(bytes)
    r.span(0_u64, 32_u64)
    raise "unsupported Mach-O magic or container" unless r.u32(0_u64) == 0xfeedfacf_u32
    cpu = r.u32(4_u64)
    raise "unsupported Mach-O CPU" unless cpu.in?(0x0100000c_u32, 0x01000007_u32)
    subtype = r.u32(8_u64)
    file_type = r.u32(12_u64)
    expected = expected_kind.object? ? 1_u32 : 2_u32
    raise "unexpected Mach-O file type" unless file_type == expected
    count = r.u32(16_u64).to_u64
    command_size = r.u32(20_u64).to_u64
    r.span(32_u64, command_size)
    raise "invalid Mach-O command count" if count > command_size // 8
    command_end = 32_u64 + command_size
    cursor = 32_u64
    sections = [] of NativeSection
    symtab = nil.as(Tuple(UInt32, UInt32, UInt32, UInt32)?)
    count.times do
      raise "truncated Mach-O command" if cursor > command_end || command_end - cursor < 8
      command = r.u32(cursor)
      size = r.u32(cursor + 4).to_u64
      raise "invalid Mach-O command size" if size < 8 || size % 8 != 0 || size > command_end - cursor
      case command
      when 0x2
        raise "invalid or duplicate Mach-O symtab" if size != 24 || symtab
        symtab = {r.u32(cursor + 8), r.u32(cursor + 12), r.u32(cursor + 16), r.u32(cursor + 20)}
      when 0x19
        raise "truncated Mach-O segment" if size < 72
        nsects = r.u32(cursor + 64).to_u64
        raise "invalid Mach-O section count" if nsects > (size - 72) // 80 || sections.size.to_u64 + nsects > 255
        nsects.times do |i|
          off = cursor + 72 + i * 80
          addr = r.u64(off + 32)
          length = r.u64(off + 40)
          raise "Mach-O section address overflow" if length > UInt64::MAX - addr
          file_offset = r.u32(off + 48)
          flags = r.u32(off + 64)
          kind = flags & 0xff
          unless kind.in?(1_u32, 0xc_u32, 0x12_u32)
            r.span(file_offset.to_u64, length)
          end
          if flags & 0x80000400 != 0 && kind != 0 && kind != 8
            raise "unsupported instruction-bearing Mach-O section"
          end
          sections << NativeSection.new(sections.size + 1, Base64.strict_encode(r.span(off + 16, 16_u64)),
            Base64.strict_encode(r.span(off, 16_u64)), hex64(addr), hex64(length), file_offset, flags)
        end
      end
      cursor += size
    end
    raise "Mach-O command size mismatch" unless cursor == command_end
    symoff, nsyms, stroff, strsize = symtab || raise "missing Mach-O symtab"
    symstart = symoff.to_u64
    symbytes = nsyms.to_u64 * 16
    strstart = stroff.to_u64
    strbytes = strsize.to_u64
    r.span(symstart, symbytes)
    strings = r.span(strstart, strbytes)
    raise "Mach-O tables overlap commands" if (symbytes > 0 && symstart < command_end) || (strbytes > 0 && strstart < command_end)
    if symbytes > 0 && strbytes > 0 && symstart < strstart + strbytes && strstart < symstart + symbytes
      raise "overlapping Mach-O tables"
    end
    # Bound the expanded evidence, not just the table: multiple nlists may
    # legally reference the same string or arbitrary suffixes. The 64 MiB
    # ceiling matches the compiler protocol message limit. Charge 256 bytes
    # per serialized record plus each decoded name and its Base64 encoding.
    budget = 64_u64 * 1024 * 1024
    records = nsyms.to_u64 + sections.size.to_u64
    raise "native evidence size limit exceeded" if records > budget // 256
    budget -= records * 256
    symbols = [] of NativeSymbol
    nsyms.to_u64.times do |i|
      off = symstart + i * 16
      strx = r.u32(off)
      name = Bytes.empty
      if strx != 0
        raise "invalid Mach-O string index" if strx >= strings.size
        end_index = strx.to_i
        while end_index < strings.size && strings[end_index] != 0
          raise "native evidence size limit exceeded" if budget == 0
          budget -= 1
          end_index += 1
        end
        raise "unterminated Mach-O symbol name" if end_index == strings.size
        encoded_size = ((end_index - strx.to_i).to_u64 + 2) // 3 * 4
        raise "native evidence size limit exceeded" if encoded_size > budget
        budget -= encoded_size
        name = strings[strx.to_i, end_index - strx.to_i]
      end
      type = r.number(off + 4, 1).to_u8
      section = r.number(off + 5, 1).to_u8
      desc = r.number(off + 6, 2).to_u16
      value = r.u64(off + 8)
      if type & 0xe0 == 0
        case type & 0x0e
        when 0x00, 0x02, 0x0c
        when 0x0a
          raise "unsupported indirect Mach-O alias"
        when 0x0e
          raise "invalid Mach-O section ordinal" if section == 0 || section > sections.size
        else
          raise "unsupported Mach-O symbol type"
        end
      end
      symbols << NativeSymbol.new(i.to_i, strx, Base64.strict_encode(name), type, section, desc, hex64(value))
    end
    NativeEvidence.new(cpu, subtype, file_type, sections, symbols)
  end

  # Called by the compiler while holding the lock on the exact link inputs.
  def self.snapshot_object(link_input_id : Int32, producer : JSON::Any, unit_name : String,
                           partition : JSON::Any, path : String, cpu : UInt32) : ObjectInput
    before = File.read(path)
    evidence = parse_native_evidence(before.to_slice, NativeKind::Object)
    raise "object CPU differs from target" unless evidence.cpu_type == cpu
    raise "link input changed during symbol inspection" unless File.read(path) == before
    ObjectInput.new(link_input_id, producer, unit_name, partition,
      ::Crystal::Digest::SHA256.hexdigest(before), Base64.strict_encode(before), evidence)
  end

  private def self.validate_object!(input : ObjectInput, expected_id : Int32) : Nil
    raise "invalid link-input ID" unless input.link_input_id == expected_id
    text(JSON::Any.new(input.unit_name))
    producer = input.producer.as_h
    case producer["kind"].as_s
    when "current_unit"
      producer = fields(input.producer, %w(kind unit_ordinal))
      raise "invalid unit ordinal" if producer["unit_ordinal"].as_i64 < 0
    when "artifact_object"
      producer = fields(input.producer, %w(kind artifact_identity object_ordinal))
      text(producer["artifact_identity"])
      raise "invalid artifact object ordinal" if producer["object_ordinal"].as_i64 < 0
    else
      raise "unknown link-input producer"
    end
    unless input.partition.raw.nil?
      partition = fields(input.partition, %w(index count))
      index = partition["index"].as_i64
      count = partition["count"].as_i64
      raise "invalid partition coordinate" unless count > 0 && index >= 0 && index < count
    end
    bytes = Base64.decode(input.bytes_base64)
    raise "invalid object encoding" unless Base64.strict_encode(bytes) == input.bytes_base64
    raise "object digest mismatch" unless ::Crystal::Digest::SHA256.hexdigest(bytes) == input.sha256
    parsed = parse_native_evidence(bytes, NativeKind::Object)
    raise "object symbol evidence mismatch" unless parsed.to_json == input.native_evidence.to_json
  end

  # Mach-O's C ABI adds one underscore to an ordinary LLVM global name.
  # LLVM's special verbatim-name prefix needs separate proof and is rejected.
  private def self.native_name(llvm_name : String) : String
    raise "unsupported LLVM verbatim symbol" if llvm_name.empty? || llvm_name.starts_with?('\u0001')
    "_#{llvm_name}"
  end

  def self.write_manifest(path : String, executable : String, bindings : Array(Binding), inputs : Array(ObjectInput), cpu : UInt32) : Nil
    raise "missing compiler link inputs" if inputs.empty?
    inputs.each_with_index do |input, index|
      validate_object!(input, index)
      raise "object CPU differs from target" unless input.native_evidence.cpu_type == cpu
    end
    current_units = {} of Int64 => Array(ObjectInput)
    inputs.each do |input|
      producer = input.producer.as_h
      next unless producer["kind"].as_s == "current_unit"
      ordinal = producer["unit_ordinal"].as_i64
      (current_units[ordinal] ||= [] of ObjectInput) << input
    end
    current_units.each_value do |objects|
      raise "inconsistent current unit names" unless objects.all? { |object| object.unit_name == objects.first.unit_name }
      if objects.first.partition.raw.nil?
        raise "duplicate or mixed single-object unit" unless objects.size == 1
      else
        first = objects.first.partition.as_h
        count = first["count"].as_i64
        indices = Set(Int64).new
        objects.each do |object|
          raise "mixed partitioned and single-object unit" if object.partition.raw.nil?
          partition = object.partition.as_h
          raise "inconsistent partition count" unless partition["count"].as_i64 == count
          raise "duplicate partition coordinate" unless indices.add?(partition["index"].as_i64)
        end
        raise "incomplete partition coverage" unless indices.size == count
      end
    end
    identities = {} of String => {JSON::Any, JSON::Any, JSON::Any, JSON::Any}
    bound_objects = Set({Int32, String}).new
    bindings.each do |binding|
      id = binding.link_input_id
      raise "binding has no link input" unless id >= 0 && id < inputs.size
      input = inputs[id]
      definition = binding.definition
      validate_definition!(definition)
      raise "binding unit mismatch" unless definition.emission.unit_name == input.unit_name
      if input.partition.raw.nil?
        raise "invalid single-object role" unless definition.partition_role == "single"
      else
        raise "invalid partition role" if definition.partition_role == "single"
      end
      name = native_name(definition.post_partition_llvm_symbol)
      raise "native object symbol does not match LLVM decoration" unless name == definition.native_object_symbol
      matches = input.native_evidence.direct_named(name)
      raise "closure definition is absent or ambiguous in its object: #{name}" unless matches.size == 1
      raise "unsupported resolver or alternate entry" unless matches.first.desc & 0x300 == 0
      raise "duplicate object binding #{name}" unless bound_objects.add?({id, name})
      emission = definition.emission
      identity = {emission.origin, emission.specialization, emission.capture_descriptor, emission.displayed_source_location}
      if previous = identities[name]?
        raise "ambiguous native closure symbol #{name}" unless previous == identity
      else
        identities[name] = identity
      end
    end

    before = File.read(executable)
    evidence = parse_native_evidence(before.to_slice, NativeKind::Executable)
    raise "executable CPU differs from target" unless evidence.cpu_type == cpu
    raise "executable changed during symbol inspection" unless File.read(executable) == before
    raise "executable symbol table is empty" if evidence.symbols.empty?
    evidence.symbols.each do |symbol|
      next unless evidence.direct_code?(symbol)
      next unless symbol.name.starts_with?("_~proc") || symbol.name.starts_with?("_~fun_literal")
      raise "linked closure has no provenance: #{symbol.name}" unless identities.has_key?(symbol.name)
    end
    linked_names = evidence.symbols.select { |symbol| evidence.direct_code?(symbol) }.map(&.name).to_set
    inputs.each do |input|
      input.native_evidence.symbols.each do |symbol|
        next unless input.native_evidence.direct_code?(symbol)
        next unless identities.has_key?(symbol.name) && linked_names.includes?(symbol.name)
        unless bound_objects.includes?({input.link_input_id, symbol.name})
          raise "unidentified competing object definition #{symbol.name}"
        end
      end
    end
    # A different or unidentified text symbol at a closure's final address is
    # an unresolved alias or fold, even when the closure's own name survived.
    by_address = {} of {UInt8, UInt64} => Array(NativeSymbol)
    evidence.symbols.each do |symbol|
      next unless evidence.direct_code?(symbol)
      (by_address[{symbol.section, symbol.value.to_u64(16)}] ||= [] of NativeSymbol) << symbol
    end
    by_address.each_value do |symbols|
      symbols.each do |symbol|
        identity = identities[symbol.name]?
        next unless identity
        raise "ambiguous executable closure definition" unless evidence.direct_named(symbol.name).size == 1
        raise "unsupported resolver or alternate entry" unless symbol.desc & 0x300 == 0
        symbols.each do |other|
          next if other.name == symbol.name
          raise "ambiguous folded executable symbol #{other.name}" unless identities[other.name]? == identity
        end
      end
    end
    manifest = JSON.build do |json|
      json.object do
        json.field "schema", 5
        json.field "object_input_scope", "compiler_supplied_link_inputs"
        json.field "executable_sha256", ::Crystal::Digest::SHA256.hexdigest(before)
        json.field "executable_symbols", evidence
        json.field "object_inputs", inputs
        json.field "bindings", bindings
      end
    end
    File.write(path, manifest)
  end
end
