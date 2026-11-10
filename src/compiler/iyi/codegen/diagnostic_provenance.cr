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

  NAME_CONTEXTS = %w(method_name definition_name macro_name local_reference instance_variable class_variable parameter path_segment type_parameter where_variable named_entry enum_member special_global regex_match_index type_self module_segment)
  MACRO_PRODUCERS = %w(ConstructedAst EmptyTupleProjection EmptyNamedTupleProjection MacroTemplate MacroId MacroVar MacroVerbatim YieldWrapper SemanticPrinter StructuredSyntax ArtifactSemanticRenderer)
  NAME_OPERATORS = %w(! != !~ % & &* &** &+ &- * ** + - / // < << <= <=> = == === =~ > >= >> [] []= []? ^ ` | ~)
  INVALID_PARAMETER_NAMES = %w(begin nil true false yield with abstract def macro require case select if unless include extend class struct module enum while until return next break lib fun alias pointerof sizeof offsetof instance_sizeof typeof private protected asm out self in end alignof instance_alignof)

  private def self.name_token?(kind : String, raw : String, mode : String, context : String) : Bool
    allowed = case context
              when "method_name"
                kind == "IDENT" || kind == "CONST" || NAME_OPERATORS.includes?(kind)
              when "definition_name"
                kind == "IDENT" || (kind != "!" && NAME_OPERATORS.includes?(kind))
              when "macro_name"
                kind == "IDENT" || kind == "CONST" || (kind != "!" && NAME_OPERATORS.includes?(kind))
              when "local_reference"
                kind == "IDENT"
              when "instance_variable"
                kind == "INSTANCE_VAR"
              when "class_variable"
                kind == "CLASS_VAR"
              when "parameter"
                kind == "IDENT" || kind == "INSTANCE_VAR" || kind == "CLASS_VAR"
              when "path_segment", "type_parameter", "where_variable", "enum_member"
                kind == "CONST"
              when "named_entry"
                kind == "IDENT" || kind == "CONST"
              when "type_self", "module_segment"
                kind == "IDENT"
              when "special_global"
                kind == "$~" || kind == "$?"
              when "regex_match_index"
                kind == "GLOBAL_MATCH_DATA_INDEX"
              else
                false
              end
    return false unless allowed
    return raw == "self" if context == "type_self"
    return raw.matches?(/\A[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*\z/) if context == "module_segment"
    return raw == kind if context == "special_global"
    if context == "regex_match_index"
      return false unless raw.matches?(/\A\$(?:0|[1-9][0-9]*\??)\z/)
      digits = raw.byte_slice(1, raw.bytesize - 1)
      digits = digits.byte_slice(0, digits.bytesize - 1) if digits.ends_with?("?")
      return digits.bytesize < 10 || (digits.bytesize == 10 && digits <= "2147483647")
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
    when "DerivedName"
      derived_name_schema4!(value, depth)
      nil
    when "Expanded"
      expansion = fields(value, %w(kind invocation_origin macro_definition_origin expansion_guard anchor_kind role name_context token_event anchor_use))
      origin_schema4!(expansion["invocation_origin"], depth + 1)
      origin_schema4!(expansion["macro_definition_origin"], depth + 1)
      guard = expansion["expansion_guard"].as_s
      raise "invalid expansion guard" unless guard.matches?(/\Asha256:[0-9a-f]{64}\z/)
      event = fields(expansion["token_event"], %w(input_start input_end token_kind token_text lexical_mode selection byte_parts))
      mode = event["lexical_mode"].as_s
      raise "invalid lexical mode" unless mode == "Crystal" || mode == "Iyi"
      raise "unknown token kind" unless Iyi::Token::Kind.values.any? { |kind| kind.to_s == event["token_kind"].as_s }
      token = event["token_text"].as_s
      raise "invalid token text" if token.empty? || !token.valid_encoding?
      first = event["input_start"].as_i64
      measured_end = event["input_end"].as_i64
      raise "invalid token extent" unless first >= 0 && measured_end <= Int32::MAX && measured_end - first == token.bytesize && measured_end > first
      use = expansion["anchor_use"].as_h
      direct = use["kind"].as_s == "Direct"
      fields(expansion["anchor_use"], %w(kind)) if direct
      last = case event["selection"].as_s
             when "Whole" then measured_end
             when "SignedNumberSign"
               valid_sign = token.bytesize >= 2 && (token.byte_at(0) == '+'.ord || token.byte_at(0) == '-'.ord) && token.byte_at(1) >= '0'.ord && token.byte_at(1) <= '9'.ord
               raise "invalid signed number selection" unless direct && expansion["anchor_kind"].as_s == "Call" && expansion["role"].as_s == "method" && event["token_kind"].as_s == "NUMBER" && valid_sign
               first + 1
             else raise "unknown token selection"
             end
      context = expansion["name_context"]
      raise "missing name context" if expansion["anchor_kind"].as_s == "Name" && context.raw.nil?
      unless context.raw.nil?
        name = context.as_s
        raise "unknown name context" unless NAME_CONTEXTS.includes?(name)
        kind, role = expansion["anchor_kind"].as_s, expansion["role"].as_s
        raise "invalid receiving name role" unless (kind == "Name" && role == name) || (kind == "Call" && role == "method" && name == "method_name")
        raise "invalid receiving name token" unless name_token?(event["token_kind"].as_s, token, mode, name)
      end
      parts = event["byte_parts"].as_a
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
          raise "structural source role mismatch" if direct && !source.valid_for_anchor?(expansion["anchor_kind"].as_s, expansion["role"].as_s)
        when "NameSplice"
          fields(part, %w(kind start_offset end_offset emitter_origin source_name))
          raise "name contribution without context" if direct && context.raw.nil?
          selected = name_value_schema4!(entry["source_name"], depth + 1)
          offset = entry["start_offset"].as_i64 - first
          length = entry["end_offset"].as_i64 - entry["start_offset"].as_i64
          raise "invalid name contribution" unless offset >= 0 && length == selected.bytesize && offset + length <= token.bytesize
          raise "name contribution differs" unless token.byte_slice(offset.to_i, length.to_i) == selected
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
      anchor_use_schema4!(value, depth)
    else
      raise "unknown diagnostic origin kind"
    end
    nil
  end

  RAW_MACRO_PRODUCERS = %w(MacroTemplate MacroId MacroVar MacroVerbatim YieldWrapper SemanticPrinter)

  private def self.same_scope?(left : Hash(String, JSON::Any), right : Hash(String, JSON::Any)) : Bool
    %w(invocation_origin macro_definition_origin expansion_guard).all? { |key| left[key] == right[key] }
  end

  private def self.raw_witness_schema4!(value : JSON::Any, spelling : String, mode : String, depth : Int32) : Nil
    event = fields(value, %w(input_start input_end token_kind token_text lexical_mode selection byte_parts))
    first, last = event["input_start"].as_i64, event["input_end"].as_i64
    raise "invalid raw witness" unless first >= 0 && last <= Int32::MAX && last - first == spelling.bytesize &&
      event["token_kind"].as_s == spelling && event["token_text"].as_s == spelling && event["selection"].as_s == "Whole" && event["lexical_mode"].as_s == mode
    raise "unknown witness token kind" unless Iyi::Token::Kind.values.any? { |kind| kind.to_s == event["token_kind"].as_s }
    parts = event["byte_parts"].as_a
    raise "missing raw witness" if parts.empty?
    cursor = first
    parts.each do |part|
      item = fields(part, %w(kind start_offset end_offset emitter_origin producer))
      start_offset, end_offset = item["start_offset"].as_i64, item["end_offset"].as_i64
      unless item["kind"].as_s == "Generated" && RAW_MACRO_PRODUCERS.includes?(item["producer"].as_s) &&
             start_offset == cursor && end_offset > cursor && end_offset <= last
        raise "invalid raw witness producer"
      end
      emitter = item["emitter_origin"]
      unless emitter.raw.nil?
        origin_schema4!(emitter, depth + 1)
        directive = Iyi::DiagnosticOrigin.from_json(emitter)
        raise "invalid witness emitter" unless directive.valid_for_anchor?("MacroDirective", "control") || directive.valid_for_anchor?("MacroDirective", "expression")
      end
      cursor = end_offset
    end
    raise "incomplete raw witness" unless cursor == last
  end

  private def self.anchor_use_schema4!(value : JSON::Any, depth : Int32) : Nil
    expanded = value.as_h
    event = expanded["token_event"].as_h
    use_value = expanded["anchor_use"]
    use = use_value.as_h
    tag = use["kind"].as_s
    return if tag == "Direct"
    rule = use["rule"].as_s
    case tag
    when "HeadOf"
      fields(use_value, %w(kind rule evidence head emitter_origin))
      parent_role = case rule
                    when "NamedArrayHead"     then {"Literal", "array"}
                    when "NamedHashHead"      then {"Literal", "hash"}
                    when "ConstantAssignHead", "ConstantTypeHead" then {"Assign", "constant"}
                    when "MultiAssignHead"    then {"Literal", "multiassign"}
                    else raise "unknown head rule"
                    end
      raise "invalid head role" unless expanded["anchor_kind"].as_s == parent_role[0] && expanded["role"].as_s == parent_role[1]
      head_value = use["head"]
      head = head_value.as_h
      case head["kind"].as_s
      when "Anchor"
        fields(head_value, %w(kind origin))
        child_value = head["origin"]
        origin_schema4!(child_value, depth + 1)
        child = child_value.as_h
        origin = Iyi::DiagnosticOrigin.from_json(child_value)
        valid = origin.valid_for_anchor?("Name", "path_segment")
        if rule == "MultiAssignHead"
          valid ||= origin.valid_for_anchor?("Call", "method") || %w(local_reference instance_variable class_variable special_global).any? { |role| origin.valid_for_anchor?("Name", role) }
          valid ||= origin.valid_for_anchor?("ProcLiteral", "arrow") || origin.valid_for_anchor?("ProcPointer", "arrow") || origin.valid_for_anchor?("Cast", "keyword")
          valid ||= %w(array hash regex interpolation range case select).any? { |role| origin.valid_for_anchor?("Literal", role) }
        end
        raise "invalid head child" unless valid && child["kind"].as_s == "Expanded" && child["anchor_use"].as_h["kind"].as_s == "Direct" && same_scope?(expanded, child) && child["token_event"] == expanded["token_event"]
      when "Syntax"
        fields(head_value, %w(kind form adjacent_name_origin))
        form = head["form"].as_s
        spelling = case form
                   when "GlobalPathPrefix" then "::"
                   when "FirstSplat" then "*"
                   when "FirstUnderscore" then "_"
                   when "ParenthesizedFirstTarget" then "("
                   else raise "unknown syntax head"
                   end
        raise "invalid syntax head" unless event["token_kind"].as_s == spelling && event["token_text"].as_s == spelling && event["selection"].as_s == "Whole"
        adjacent = head["adjacent_name_origin"]
        if form == "GlobalPathPrefix"
          origin_schema4!(adjacent, depth + 1)
          child = adjacent.as_h
          origin = Iyi::DiagnosticOrigin.from_json(adjacent)
          child_event = child["token_event"].as_h
          unless origin.valid_for_anchor?("Name", "path_segment") && child["kind"].as_s == "Expanded" &&
                 child["anchor_use"].as_h["kind"].as_s == "Direct" && same_scope?(expanded, child) &&
                 child_event["input_start"].as_i64 == event["input_end"].as_i64 && child_event["selection"].as_s == "Whole" &&
                 child_event["token_kind"].as_s == "CONST" && child_event["lexical_mode"] == event["lexical_mode"]
            raise "invalid global path head"
          end
        elsif rule != "MultiAssignHead" || !adjacent.raw.nil?
          raise "invalid first target head"
        end
      else
        raise "unknown head kind"
      end
    when "PayloadOf"
      fields(use_value, %w(kind rule evidence owner_origin emitter_origin))
      owner_value = use["owner_origin"]
      origin_schema4!(owner_value, depth + 1)
      owner = owner_value.as_h
      origin = Iyi::DiagnosticOrigin.from_json(owner_value)
      unless expanded["anchor_kind"].as_s == "Literal" && expanded["role"].as_s == "interpolation" && expanded["name_context"].raw.nil? &&
             owner["kind"].as_s == "Expanded" && owner["anchor_use"].as_h["kind"].as_s == "Direct" && same_scope?(expanded, owner) && owner["token_event"] == expanded["token_event"]
        raise "invalid payload owner"
      end
      raise "invalid payload delimiter" unless event["token_kind"].as_s == "DELIMITER_START" && event["selection"].as_s == "Whole"
      opener = event["token_text"].as_s
      case rule
      when "RegexInterpolationPayload"
        valid_opener = opener == "/" || (opener.bytesize == 3 && opener.starts_with?("%r") && "(<[{|".includes?(opener[2]))
        raise "invalid regex owner" unless origin.valid_for_anchor?("Literal", "regex") && valid_opener
      when "CommandInterpolationPayload"
        valid_opener = opener == "`" || (opener.bytesize == 3 && opener.starts_with?("%x") && "(<[{|".includes?(opener[2]))
        raise "invalid command owner" unless origin.valid_for_anchor?("Call", "method") && valid_opener
      else raise "unknown payload rule"
      end
    else
      raise "unknown anchor use"
    end
    evidence_value = use["evidence"]
    evidence = evidence_value.as_h
    emitter = use["emitter_origin"]
    unless emitter.raw.nil?
      origin_schema4!(emitter, depth + 1)
      directive = Iyi::DiagnosticOrigin.from_json(emitter)
      raise "invalid anchor use emitter" unless directive.valid_for_anchor?("MacroDirective", "expression") || directive.valid_for_anchor?("MacroDirective", "control")
      raise "invalid inferred emitter" if {"RawSyntax", "DerivedFromOwner"}.includes?(evidence["kind"].as_s)
    end
    case evidence["kind"].as_s
    when "Spliced"
      fields(evidence_value, %w(kind source_origin))
      source = evidence["source_origin"]
      origin_schema4!(source, depth + 1)
      raise "invalid preserved parent" unless Iyi::DiagnosticOrigin.from_json(source).valid_for_anchor?(expanded["anchor_kind"].as_s, expanded["role"].as_s)
    when "Constructed"
      fields(evidence_value, %w(kind producer))
      raise "invalid constructed parent" unless evidence["producer"].as_s == "ConstructedAst"
    when "DerivedFromOwner"
      fields(evidence_value, %w(kind))
      raw = event["byte_parts"].as_a.all? { |part| part.as_h["kind"].as_s == "Generated" && RAW_MACRO_PRODUCERS.includes?(part.as_h["producer"].as_s) }
      raise "invalid derived payload" unless tag == "PayloadOf" && raw
    when "RawSyntax"
      fields(evidence_value, %w(kind witnesses))
      raise "invalid raw syntax use" unless tag == "HeadOf"
      forms = case rule
              when "NamedArrayHead", "NamedHashHead" then [{"Open", "{"}]
              when "ConstantAssignHead" then [{"Equals", "="}]
              when "ConstantTypeHead" then [{"Colon", ":"}, {"Equals", "="}]
              when "MultiAssignHead"
                if use["head"].as_h["form"]?.try(&.as_s) == "FirstSplat"
                  [{"Splat", "*"}, {"Equals", "="}]
                else
                  [{"Comma", ","}, {"Equals", "="}]
                end
              else raise "unknown witness rule"
              end
      witnesses = evidence["witnesses"].as_a
      raise "missing witnesses" unless witnesses.size == forms.size
      last = event["input_end"].as_i64
      witnesses.each_with_index do |witness, index|
        item = fields(witness, %w(role event))
        role, spelling = forms[index]
        witness_event = item["event"].as_h
        same_splat = rule == "MultiAssignHead" && role == "Splat" && index == 0
        ordered = same_splat ? item["event"] == expanded["token_event"] : witness_event["input_start"].as_i64 >= last
        raise "invalid witness order" unless item["role"].as_s == role && ordered
        raw_witness_schema4!(item["event"], spelling, event["lexical_mode"].as_s, depth)
        last = witness_event["input_end"].as_i64
      end
    else
      raise "unknown use evidence"
    end
  end

  private def self.type_sugar_schema4!(value : JSON::Any, depth : Int32) : Tuple(String, String)
    item = fields(value, %w(kind derivation_kind production witnesses result lowering_index))
    production, result = item["production"].as_s, item["result"].as_s
    index = item["lowering_index"].as_i64
    spellings, allowed = case production
                         when "Pointer" then {["*"], result == "Pointer" && index == 0}
                         when "DoublePointer" then {["**"], result == "Pointer" && (index == 0 || index == 1)}
                         when "NilableType" then {["?"], result == "Nil" && index == 0}
                         when "NilableExpression" then {["?"], {"Union", "Nil"}.includes?(result) && index == 0}
                         when "SelfNilableType" then {["self?"], {"Nil", "Self"}.includes?(result) && index == 0}
                         when "StaticArray" then {["[", "]"], result == "StaticArray" && index == 0}
                         when "Tuple" then {["{", "}"], result == "Tuple" && index == 0}
                         when "NamedTuple" then {["{", "}"], result == "NamedTuple" && index == 0}
                         when "NilPredicate" then {["nil?"], result == "Nil" && index == 0}
                         else raise "unknown type sugar"
                         end
    raise "invalid type sugar result" unless allowed
    witnesses = item["witnesses"].as_a
    raise "invalid type sugar witnesses" unless witnesses.size == spellings.size
    previous = -1_i64
    common_digest = nil.as(String?)
    common_size = -1_i64
    common_mode = nil.as(String?)
    common_origin = nil.as(JSON::Any?)
    witnesses.each_with_index do |value_token, ordinal|
      token = fields(value_token, %w(lexical_origin input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
      lexical = token["lexical_origin"]
      origin_schema4!(lexical, depth + 1)
      raise "invalid type syntax origin" unless Iyi::DiagnosticOrigin.from_json(lexical).valid_for_anchor?("TypeSyntax", "token")
      digest, mode = token["input_sha256"].as_s, token["lexical_mode"].as_s
      raise "invalid type syntax input" unless digest.matches?(/\A[0-9a-f]{64}\z/) && (mode == "Crystal" || mode == "Iyi")
      size, first, last = token["input_bytesize"].as_i64, token["input_start"].as_i64, token["input_end"].as_i64
      spelling = spellings[ordinal]
      expected_kind = {"self?", "nil?"}.includes?(spelling) ? "IDENT" : spelling
      unless token["token_kind"].as_s == expected_kind && token["raw_text"].as_s == spelling &&
             first >= 0 && first >= previous && size <= Int32::MAX && last <= size && last - first == spelling.bytesize
        raise "invalid type syntax token"
      end
      source = lexical.as_h
      case source["kind"].as_s
      when "Written"
        raise "type syntax offset mismatch" unless source["input_byte_offset"].as_i64 == first
      when "Expanded"
        event = source["token_event"].as_h
        unless source["expansion_guard"].as_s == "sha256:#{digest}" && event["selection"].as_s == "Whole" &&
               event["input_start"].as_i64 == first && event["input_end"].as_i64 == last &&
               event["token_kind"].as_s == expected_kind && event["token_text"].as_s == spelling && event["lexical_mode"].as_s == mode
          raise "expanded type syntax mismatch"
        end
      else
        raise "invalid type syntax source"
      end
      if ordinal > 0
        prior = common_origin.not_nil!.as_h
        same_source = prior["kind"] == source["kind"] && case source["kind"].as_s
                      when "Written" then prior["source_identity"] == source["source_identity"]
                      when "Expanded" then same_scope?(prior, source)
                      else false
                      end
        raise "type syntax input mismatch" unless common_digest == digest && common_size == size && common_mode == mode && same_source
      end
      common_digest, common_size, common_mode, previous, common_origin = digest, size, mode, last, lexical
    end
    {result == "Self" ? "type_self" : "path_segment", result == "Self" ? "self" : result}
  end

  private def self.bound_projection_schema4!(value : JSON::Any, depth : Int32) : Tuple(String, String)
    item = fields(value, %w(kind derivation_kind producer source_fragment_sha256 source_text source_names output_text lexical_mode result_start result_end token_kind context))
    source, output = item["source_text"].as_s, item["output_text"].as_s
    raise "bound projection requires authoritative source inventory" unless source.empty?
    raise "invalid projection UTF-8" unless source.valid_encoding? && output.valid_encoding?
    raise "projection source guard mismatch" unless ::Crystal::Digest::SHA256.hexdigest(source) == item["source_fragment_sha256"].as_s
    names = item["source_names"].as_a
    cursor = 0_i64
    names.each do |entry|
      name = fields(entry, %w(start_offset end_offset name))
      first, last = name["start_offset"].as_i64, name["end_offset"].as_i64
      raise "invalid projection source span" unless first >= cursor && last > first && last <= source.bytesize
      bytes = source.byte_slice(first.to_i, (last - first).to_i)
      raise "invalid projection source name" unless bytes.valid_encoding? && bytes == name_value_schema4!(name["name"], depth + 1)
      cursor = last
    end
    producer_value = item["producer"]
    producer = producer_value.as_h
    producer.each_value do |field|
      if text = field.raw.as?(String)
        raise "invalid producer UTF-8" unless text.valid_encoding?
      end
    end
    kind = producer["kind"].as_s
    permitted = %w(path_segment named_entry type_self)
    actual = case kind
             when "StripRoot"
               fields(producer_value, %w(kind root))
               root = producer["root"].as_s
               prefix = "#{root}::"
               raise "invalid root projection" if root.empty? || names.empty? || !source.starts_with?(prefix)
               permitted = %w(path_segment)
               source.byte_slice(prefix.bytesize, source.bytesize - prefix.bytesize)
             when "ForeignType"
               fields(producer_value, %w(kind module_name source_name qualified_name))
               module_name, old, replacement = producer["module_name"].as_s, producer["source_name"].as_s, producer["qualified_name"].as_s
               raise "invalid foreign projection" if module_name.empty? || old.empty? || replacement.empty? || names.empty? || !(source == old || source.starts_with?("#{old}::"))
               permitted = %w(path_segment)
               replacement + source.byte_slice(old.bytesize, source.bytesize - old.bytesize)
             when "AliasType"
               fields(producer_value, %w(kind owner name resolved_type))
               owner, name, replacement = producer["owner"].as_s, producer["name"].as_s, producer["resolved_type"].as_s
               raise "invalid alias projection" if owner.empty? || name.empty? || replacement.empty? || names.empty? || source != name
               replacement
             when "SelfReturn"
               fields(producer_value, %w(kind owner_type method_name receiver))
               owner = producer["owner_type"].as_s
               raise "invalid self return" if owner.empty? || names.empty? || source != owner || producer["method_name"].as_s != "new" || producer["receiver"].as_s != "self"
               permitted = %w(type_self)
               "self"
             when "SemanticSignatureType"
               fields(producer_value, %w(kind definition_origin field parameter_index semantic_type))
               definition = producer["definition_origin"]
               origin_schema4!(definition, depth + 1)
               raise "invalid signature producer" unless source.empty? && names.empty? && Iyi::DiagnosticOrigin.from_json(definition).valid_for_anchor?("Def", "keyword")
               parameter = producer["parameter_index"]
               case producer["field"].as_s
               when "return_type"
                 raise "invalid return index" unless parameter.raw.nil?
               when "parameter_restriction"
                 index = parameter.as_i64
                 raise "invalid parameter index" unless index >= 0 && index <= Int32::MAX
               else raise "unknown signature field"
               end
               type = producer["semantic_type"].as_s
               raise "empty semantic type" if type.empty?
               type
             when "UninitializedClassVar"
               fields(producer_value, %w(kind declaration_origin owner_type variable_name semantic_type))
               declaration = producer["declaration_origin"]
               origin_schema4!(declaration, depth + 1)
               owner, variable, type = producer["owner_type"].as_s, producer["variable_name"].as_s, producer["semantic_type"].as_s
               unless source.empty? && names.empty? && !owner.empty? && !type.empty? &&
                      Iyi::DiagnosticOrigin.from_json(declaration).valid_for_anchor?("Name", "class_variable") &&
                      name_token?("CLASS_VAR", variable, item["lexical_mode"].as_s, "class_variable")
                 raise "invalid uninitialized class variable"
               end
               "uninitialized #{type}"
             when "ConstantAccessor"
               fields(producer_value, %w(kind definition_origin prefix constant_name part))
               definition = producer["definition_origin"]
               origin_schema4!(definition, depth + 1)
               origin = definition.as_h
               unless source.empty? && names.empty? && !producer["constant_name"].as_s.empty? &&
                      Iyi::DiagnosticOrigin.from_json(definition).valid_for_anchor?("Def", "keyword") &&
                      origin["kind"].as_s == "Synthetic" && origin["synthesis_kind"].as_s == "constant_accessor" && origin["structural_slot"].as_s == "getter"
                 raise "invalid accessor producer"
               end
               case producer["part"].as_s
               when "Name"
                 permitted = %w(definition_name)
                 (producer["prefix"].as_s + producer["constant_name"].as_s).downcase
               when "Receiver"
                 permitted = %w(local_reference)
                 "self"
               else raise "invalid accessor part"
               end
             when "ResolvedRestriction"
               fields(producer_value, %w(kind owner_type written_type resolved_type root add_global))
               owner, written, resolved, root = producer["owner_type"].as_s, producer["written_type"].as_s, producer["resolved_type"].as_s, producer["root"].as_s
               add_global = producer["add_global"].as_bool
               raise "invalid resolved restriction" if owner.empty? || written.empty? || resolved.empty? || names.empty? || source != written
               if add_global && (resolved.starts_with?("::") || resolved.partition("::")[0].empty? || resolved.partition("::")[0] == root)
                 raise "invalid global restriction"
               end
               add_global ? "::#{resolved}" : resolved
             else raise "unknown bound producer"
             end
    context, mode = item["context"].as_s, item["lexical_mode"].as_s
    raise "invalid bound projection result" unless actual == output && permitted.includes?(context) && {"Crystal", "Iyi"}.includes?(mode)
    first, last = item["result_start"].as_i64, item["result_end"].as_i64
    raise "invalid projection result span" unless first >= 0 && last > first && last <= output.bytesize && (kind != "UninitializedClassVar" || first >= "uninitialized ".bytesize)
    lex_context = context == "definition_name" ? Iyi::DiagnosticRenderedLexContext::DefOrMacroName : Iyi::DiagnosticRenderedLexContext::TypeName
    observed = Iyi::DiagnosticRenderedTokens.observe_one(output, first.to_i, last.to_i, mode, lex_context)
    unless observed.token_kind == item["token_kind"].as_s && name_token?(observed.token_kind, observed.token_text, mode, context)
      raise "invalid projection result token"
    end
    following = output.byte_slice(last.to_i, output.bytesize - last.to_i).lstrip
    while following.starts_with?("#")
      newline = following.byte_index('\n')
      following = newline ? following.byte_slice(newline + 1, following.bytesize - newline - 1).lstrip : ""
    end
    named_entry = following.starts_with?(":") && !following.starts_with?("::")
    raise "invalid projected type position" unless (context == "named_entry") == named_entry
    unless kind == "ConstantAccessor"
      prefix = kind == "UninitializedClassVar" ? "uninitialized ".bytesize : 0
      type_text = output.byte_slice(prefix, output.bytesize - prefix)
      parser = Iyi::Parser.new(type_text)
      parser.iyi = mode == "Iyi"
      parser.enable_diagnostic_name_observations
      parser.next_token
      parser.parse_bare_proc_type
      parser.check :EOF
      matched = parser.diagnostic_name_observations.any? do |entry|
        entry.input_start + prefix == first && entry.input_end + prefix == last &&
          entry.token_kind == item["token_kind"].as_s && entry.context == context && entry.token_text == observed.token_text
      end
      raise "bound token is not an accepted type name" unless matched
    end
    {context, observed.token_text}
  end

  private def self.derived_name_schema4!(value : JSON::Any, depth : Int32) : Tuple(String, String)
    raise "diagnostic origin nesting too deep" if depth > 128
    object = value.as_h
    raise "invalid derived origin kind" unless object["kind"].as_s == "DerivedName"
    return bound_projection_schema4!(value, depth) if object["derivation_kind"].as_s == "BoundProjection"
    if object["derivation_kind"].as_s == "ModuleHeaderPath"
      item = fields(value, %w(kind derivation_kind module_header_origin source_segments package_name result_index))
      header = item["module_header_origin"]
      origin_schema4!(header, depth + 1)
      unless {"Written", "Expanded"}.includes?(header.as_h["kind"].as_s) && Iyi::DiagnosticOrigin.from_json(header).valid_for_anchor?("ModuleHeader", "keyword")
        raise "invalid module header origin"
      end
      segments = item["source_segments"].as_a
      raise "missing module path segments" if segments.empty?
      names = [] of String
      previous = -1_i64
      prior_token = nil.as(Hash(String, JSON::Any)?)
      segments.each do |token_value|
        source_name_schema4!(token_value, depth + 1)
        token = token_value.as_h
        unless token["context"].as_s == "module_segment" && token["binding_origin"].raw.nil? && token["input_start"].as_i64 >= previous
          raise "invalid module segment"
        end
        if prior = prior_token
          left, right = prior["lexical_origin"].as_h, token["lexical_origin"].as_h
          same_identity = left["kind"] == right["kind"] && case left["kind"].as_s
                          when "Written" then left["source_identity"] == right["source_identity"]
                          when "Expanded" then same_scope?(left, right)
                          else false
                          end
          unless prior["input_sha256"] == token["input_sha256"] && prior["input_bytesize"] == token["input_bytesize"] &&
                 prior["lexical_mode"] == token["lexical_mode"] && same_identity
            raise "module segment input mismatch"
          end
        end
        names << token["raw_text"].as_s
        prior_token = token
        previous = token["input_end"].as_i64
      end
      package = item["package_name"]
      unless package.raw.nil?
        name = package.as_s
        raise "invalid package name" if name.empty? || !name.valid_encoding?
        names.unshift(name) unless names.first == name
      end
      index = item["result_index"].as_i64
      raise "invalid module segment index" unless index >= 0 && index < names.size
      rendered = names[index.to_i].camelcase
      raise "invalid rendered module segment" unless name_token?("CONST", rendered, "Iyi", "path_segment")
      return {"path_segment", rendered}
    end
    if object["derivation_kind"].as_s == "ImplicitModuleSelf"
      item = fields(value, %w(kind derivation_kind module_header_origin))
      header = item["module_header_origin"]
      origin_schema4!(header, depth + 1)
      kind = header.as_h["kind"].as_s
      unless {"Written", "Expanded"}.includes?(kind) && Iyi::DiagnosticOrigin.from_json(header).valid_for_anchor?("ModuleHeader", "keyword")
        raise "invalid implicit module self origin"
      end
      return {"type_self", "self"}
    end
    return type_sugar_schema4!(value, depth) if object["derivation_kind"].as_s == "TypeSugar"
    if object["derivation_kind"].as_s == "RegexMatchIndex"
      item = fields(value, %w(kind derivation_kind source_token result))
      source_name_schema4!(item["source_token"], depth + 1)
      source = item["source_token"].as_h
      lexical = Iyi::DiagnosticOrigin.from_json(source["lexical_origin"])
      raise "invalid regex derivation source" unless source["context"].as_s == "regex_match_index" && lexical.valid_for_anchor?("Name", "regex_match_index")
      case item["result"].as_s
      when "MatchData" then return {"special_global", "$~"}
      when "Lookup"    then return {"method", source["raw_text"].as_s.ends_with?("?") ? "[]?" : "[]"}
      else                   raise "invalid regex derivation result"
      end
    end
    raise "unknown derived name operation" unless object["derivation_kind"].as_s == "ParameterLowering"
    item = fields(value, %w(kind derivation_kind source_token definition_origin parameter_slot parameter_index result projection fresh_index))
    source = item["source_token"].as_h
    source_name_schema4!(item["source_token"], depth + 1)
    lexical = Iyi::DiagnosticOrigin.from_json(source["lexical_origin"])
    raise "invalid derived source role" unless source["context"].as_s == "parameter" && lexical.valid_for_anchor?("Name", "parameter")
    prefix = case source["token_kind"].as_s
             when "INSTANCE_VAR" then "@"
             when "CLASS_VAR"    then "@@"
             else                     ""
             end
    raw = source["raw_text"].as_s
    raise "invalid variable prefix" if prefix.empty? || !raw.starts_with?(prefix)
    definition = item["definition_origin"]
    origin_schema4!(definition, depth + 1)
    raise "invalid derived definition owner" unless Iyi::DiagnosticOrigin.from_json(definition).valid_for_anchor?("Def", "keyword")
    slot = item["parameter_slot"].as_s
    index = item["parameter_index"].as_i64
    raise "invalid parameter slot" unless %w(positional double_splat block).includes?(slot)
    raise "invalid parameter index" unless index >= 0 && index <= Int32::MAX && (slot == "positional" || index == 0)
    stem = raw.byte_slice(prefix.bytesize, raw.bytesize - prefix.bytesize)
    raise "invalid UTF-8 projection" unless stem.valid_encoding?
    invalid_stem = INVALID_PARAMETER_NAMES.includes?(stem)
    result, projection, fresh = item["result"].as_s, item["projection"].as_s, item["fresh_index"]
    if result == "Target" && projection == "Whole" && fresh.raw.nil?
      return {prefix == "@" ? "instance_variable" : "class_variable", raw}
    elsif result == "DefaultExternal" && projection == "StripVariablePrefix" && fresh.raw.nil? && invalid_stem
      return {"named_entry", stem}
    elsif result == "Argument" || result == "LocalValue"
      role = result == "Argument" ? "parameter" : "local_reference"
      if projection == "StripVariablePrefix" && fresh.raw.nil? && !invalid_stem
        return {role, stem}
      elsif projection == "FreshParameterName" && invalid_stem
        fresh_index = fresh.as_i64
        raise "invalid fresh index" unless fresh_index >= 0 && fresh_index <= Int32::MAX
        return {role, "__arg#{fresh_index}"}
      end
    end
    raise "invalid derived name operation"
  end

  private def self.name_value_schema4!(value : JSON::Any, depth : Int32) : String
    case value.as_h["kind"].as_s
    when "Observed"
      item = fields(value, %w(kind source_token))
      source_name_schema4!(item["source_token"], depth)
      item["source_token"].as_h["raw_text"].as_s
    when "Derived"
      item = fields(value, %w(kind origin))
      derived_name_schema4!(item["origin"], depth)[1]
    else
      raise "unknown name value"
    end
  end

  private def self.source_name_schema4!(value : JSON::Any, depth : Int32) : Nil
    source = fields(value, %w(lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text))
    context = source["context"].as_s
    raise "unknown source name context" unless NAME_CONTEXTS.includes?(context)
    lexical = source["lexical_origin"]
    origin_schema4!(lexical, depth)
    origin = Iyi::DiagnosticOrigin.from_json(lexical)
    raise "invalid source name role" unless origin.valid_for_anchor?("Name", context) || (%w(method_name local_reference).includes?(context) && origin.valid_for_anchor?("Call", "method"))
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
      event = expanded["token_event"].as_h
      raise "expanded source mismatch" unless event["input_start"].as_i64 == first && event["input_end"].as_i64 == last && expanded["expansion_guard"].as_s == "sha256:#{digest}" && event["token_text"].as_s == raw && event["token_kind"] == source["token_kind"] && event["lexical_mode"] == source["lexical_mode"] && event["selection"].as_s == "Whole"
    else
      raise "invalid source lexical origin"
    end
  end

  private def self.validated_origin(value : JSON::Any) : Iyi::DiagnosticOrigin
    bound_origin!(value)
    origin_schema4!(value)
    events = {} of Tuple(String, String, String, Int64) => JSON::Any
    pending = [value]
    until pending.empty?
      item = pending.pop
      case raw = item.raw
      when Array
        raw.each { |child| pending << child }
      when Hash
        if raw["kind"]?.try(&.as_s) == "Expanded"
          associated = [raw["token_event"]]
          use = raw["anchor_use"].as_h
          if use["kind"].as_s == "HeadOf" && use["evidence"].as_h["kind"].as_s == "RawSyntax"
            use["evidence"].as_h["witnesses"].as_a.each { |witness| associated << witness.as_h["event"] }
          end
          associated.each do |event|
            key = {raw["invocation_origin"].to_json, raw["macro_definition_origin"].to_json,
                   raw["expansion_guard"].as_s, event.as_h["input_start"].as_i64}
            if previous = events[key]?
              raise "conflicting token event identity" unless previous == event
            else
              events[key] = event
            end
          end
        end
        raw.each_value { |child| pending << child }
      end
    end
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
