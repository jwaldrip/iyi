require "json"
require "base64"
require "set"
require "crystal/digest/sha256"
require "../syntax/diagnostic_origin"

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

  struct NativeSymbol
    include JSON::Serializable

    getter name : String
    getter address : String
    getter kind : String

    def initialize(@name, @address, @kind)
    end
  end

  struct NativeEvidence
    include JSON::Serializable

    getter raw_nm : String
    getter symbols : Array(NativeSymbol)

    def initialize(@raw_nm, @symbols)
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
      Iyi::DiagnosticOrigin.from_json(scope["origin"])
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
    origin = Iyi::DiagnosticOrigin.from_json(binding["binding_origin"])
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
    Iyi::DiagnosticOrigin.from_json(block["origin"])
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
      Iyi::DiagnosticOrigin.from_json(scope["origin"])
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
    Iyi::DiagnosticOrigin.from_json(spec["definition_origin"])
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
    origin = Iyi::DiagnosticOrigin.from_json(record.origin)
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

  # Mach-O `nm -m -U`: address, section, visibility, and the entire remaining
  # symbol name. Unknown output is not guessed or treated as a definition.
  def self.parse_native_evidence(raw : String) : NativeEvidence
    symbols = [] of NativeSymbol
    raw.each_line do |line|
      line = line.chomp
      next if line.empty?
      match = /\A([0-9a-fA-F]+)\s+\(([^()]*)\)\s+((?:weak\s+)?(?:private\s+)?external|non-external)\s+(.+)\z/.match(line)
      raise "unsupported nm definition: #{line}" unless match
      address = match[1]
      address.to_u64(16)
      name = match[4]
      raise "unsupported annotated nm symbol: #{name}" if name.includes?(" (was a private external)")
      symbols << NativeSymbol.new(name, address, "#{match[2]} #{match[3]}")
    end
    NativeEvidence.new(raw, symbols)
  end

  def self.native_evidence(path : String) : NativeEvidence
    output = IO::Memory.new
    error = IO::Memory.new
    status = Process.run("nm", ["-m", "-U", path], output: output, error: error)
    raise "cannot inspect native definitions: #{error}" unless status.success?
    parse_native_evidence(output.to_s)
  end

  # Called by the compiler while holding the lock on the exact link inputs.
  def self.snapshot_object(link_input_id : Int32, producer : JSON::Any, unit_name : String,
                           partition : JSON::Any, path : String) : ObjectInput
    before = File.read(path)
    evidence = native_evidence(path)
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
    parsed = parse_native_evidence(input.native_evidence.raw_nm).symbols
    recorded = input.native_evidence.symbols
    raise "object symbol evidence mismatch" unless parsed.size == recorded.size
    parsed.each_with_index do |symbol, index|
      other = recorded[index]
      unless {symbol.name, symbol.address, symbol.kind} == {other.name, other.address, other.kind}
        raise "object symbol evidence mismatch"
      end
    end
  end

  # Mach-O's C ABI adds one underscore to an ordinary LLVM global name.
  # LLVM's special verbatim-name prefix needs separate proof and is rejected.
  private def self.native_name(llvm_name : String) : String
    raise "unsupported LLVM verbatim symbol" if llvm_name.empty? || llvm_name.starts_with?('\u0001')
    "_#{llvm_name}"
  end

  def self.write_manifest(path : String, executable : String, bindings : Array(Binding), inputs : Array(ObjectInput)) : Nil
    raise "missing compiler link inputs" if inputs.empty?
    inputs.each_with_index { |input, index| validate_object!(input, index) }
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
      unless input.native_evidence.symbols.any? { |symbol| symbol.name == name && symbol.kind.starts_with?("__TEXT,__text ") }
        raise "closure definition is absent from its object: #{name}"
      end
      bound_objects.add({id, name})
      emission = definition.emission
      identity = {emission.origin, emission.specialization, emission.capture_descriptor, emission.displayed_source_location}
      if previous = identities[name]?
        raise "ambiguous native closure symbol #{name}" unless previous == identity
      else
        identities[name] = identity
      end
    end

    before = File.read(executable)
    evidence = native_evidence(executable)
    raise "executable changed during symbol inspection" unless File.read(executable) == before
    raise "executable symbol table is empty" if evidence.symbols.empty?
    evidence.symbols.each do |symbol|
      next unless symbol.kind.starts_with?("__TEXT,__text ")
      next unless symbol.name.starts_with?("_~proc") || symbol.name.starts_with?("_~fun_literal")
      raise "linked closure has no provenance: #{symbol.name}" unless identities.has_key?(symbol.name)
    end
    linked_names = evidence.symbols.map(&.name).to_set
    inputs.each do |input|
      input.native_evidence.symbols.each do |symbol|
        next unless symbol.kind.starts_with?("__TEXT,__text ")
        next unless identities.has_key?(symbol.name) && linked_names.includes?(symbol.name)
        unless bound_objects.includes?({input.link_input_id, symbol.name})
          raise "unidentified competing object definition #{symbol.name}"
        end
      end
    end
    # A different or unidentified text symbol at a closure's final address is
    # an unresolved alias or fold, even when the closure's own name survived.
    by_address = {} of UInt64 => Array(NativeSymbol)
    evidence.symbols.each do |symbol|
      next unless symbol.kind.starts_with?("__TEXT,__text ")
      (by_address[symbol.address.to_u64(16)] ||= [] of NativeSymbol) << symbol
    end
    by_address.each_value do |symbols|
      symbols.each do |symbol|
        identity = identities[symbol.name]?
        next unless identity
        symbols.each do |other|
          next if other.name == symbol.name
          raise "ambiguous folded executable symbol #{other.name}" unless identities[other.name]? == identity
        end
      end
    end
    manifest = JSON.build do |json|
      json.object do
        json.field "schema", 2
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
