require "json"
require "base64"
require "set"
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
    FRESH_CONTRACT_FIELDS = %w(entry_rule filename input_offset_base lexical_journal_enabled lexical_mode package
      diagnostic_capture source_unit source_only reads_using module_extends_written visibility def_nest fun_nest
      type_nest wants_doc doc_enabled comments_enabled count_whitespace wants_raw slash_is_regex wants_regex
      wants_def_or_macro_name wants_symbol scopes)

    getter kind : DiagnosticCaptureInputKind
    @logical_module : String?
    @package : String?
    @original_file : String?
    @lexical_mode : String
    getter entry : DiagnosticCaptureParseEntry
    getter mode : DiagnosticCaptureParseMode
    getter module_extends_written : Bool
    getter source_only : Bool
    getter visibility : Visibility?
    getter def_nest : Int32
    getter fun_nest : Int32
    getter type_nest : Int32
    getter wants_doc : Bool
    @input_sha256 : String
    @input : String
    @scopes : Array(Array(String))
    @warning_policy : WarningCollection::ParseAheadPolicy
    @warning_policy_json : String
    @fresh_parser_contract : String

    def initialize(input : String, @kind : DiagnosticCaptureInputKind,
                   @logical_module : String?, @package : String?, @original_file : String?,
                   @lexical_mode : String, @entry : DiagnosticCaptureParseEntry,
                   @mode : DiagnosticCaptureParseMode, @module_extends_written : Bool,
                   @source_only : Bool, @visibility : Visibility?, @def_nest : Int32,
                   @fun_nest : Int32, @type_nest : Int32, @wants_doc : Bool,
                   scopes : Array(Array(String)), warning_policy : WarningCollection::ParseAheadPolicy,
                   fresh_parser_contract : String)
      raise ArgumentError.new("capture input exceeds 64 MiB") if input.bytesize > MAX_INPUT_BYTES
      raise ArgumentError.new("capture input is not UTF-8") unless input.valid_encoding?
      raise ArgumentError.new("unknown capture lexical mode") unless {"Iyi", "Crystal"}.includes?(@lexical_mode)
      raise ArgumentError.new("invalid capture nesting") if @def_nest < 0 || @fun_nest < 0 || @type_nest < 0
      raise ArgumentError.new("capture parser scopes missing") if scopes.empty?
      raise ArgumentError.new("parser contract exceeds size limit") if fresh_parser_contract.bytesize.to_u64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES
      scope_budget = DiagnosticOrigin::MAX_UNFOLDED_BYTES
      raise ArgumentError.new("parser scopes exceed size limit") if scopes.size.to_u64 * 32_u64 > scope_budget
      scope_budget -= scopes.size.to_u64 * 32_u64
      scopes.each do |scope|
        raise ArgumentError.new("parser scope exceeds size limit") if scope.size.to_u64 * 32_u64 > scope_budget
        scope_budget -= scope.size.to_u64 * 32_u64
        scope.each do |name|
          raise ArgumentError.new("parser scope exceeds size limit") if name.bytesize.to_u64 > scope_budget
          scope_budget -= name.bytesize.to_u64
        end
      end
      if @entry.parse_to_def?
        raise ArgumentError.new("parse_to_def capture requires its original Def context")
      end
      if @kind.macro_expansion?
        raise ArgumentError.new("macro capture requires expansion binding, parent lineage, and pragma inputs")
      end
      unless @kind.source_file? || @kind.entry_buffer?
        raise ArgumentError.new("unknown capture input kind")
      end
      unless @entry.parse? || @entry.parse_mode?
        raise ArgumentError.new("unknown capture parse entry")
      end
      unless @mode.normal? || @mode.lib? || @mode.lib_struct_or_union? || @mode.enum?
        raise ArgumentError.new("unknown capture parse mode")
      end
      if @kind.source_file? && (@original_file.nil? || @original_file.not_nil!.empty?)
        raise ArgumentError.new("source capture requires original file identity")
      end
      unless warning_policy.class == WarningCollection::ParseAheadPolicy &&
             warning_policy.policy_bytes <= WarningCollection::ParseAheadPolicy::MAX_POLICY_BYTES &&
             warning_policy.excluded_path_count <= WarningCollection::ParseAheadPolicy::MAX_EXCLUDED_PATHS
        raise ArgumentError.new("unclassified or oversized warning policy")
      end
      policy_json = warning_policy.fingerprint
      raise ArgumentError.new("serialized warning policy exceeds size limit") if policy_json.bytesize > MAX_INPUT_BYTES
      @warning_policy = WarningCollection::ParseAheadPolicy.new(warning_policy.level,
        warning_policy.excluded_paths, warning_policy.lib_path, warning_policy.explain_spawn,
        warning_policy.error_on_warnings?)
      @warning_policy_json = String.new(@warning_policy.fingerprint.to_slice)
      raise ArgumentError.new("warning policy changed during snapshot") unless @warning_policy_json == policy_json
      @logical_module = @logical_module.try { |value| String.new(value.to_slice) }
      @package = @package.try { |value| String.new(value.to_slice) }
      @original_file = @original_file.try { |value| String.new(value.to_slice) }
      @lexical_mode = String.new(@lexical_mode.to_slice)
      @input = String.new(input.to_slice)
      @input_sha256 = ::Crystal::Digest::SHA256.hexdigest(@input)
      @scopes = scopes.map { |scope| scope.map { |name| String.new(name.to_slice) } }
      @fresh_parser_contract = String.new(fresh_parser_contract.to_slice)
      validate_fresh_parser_contract!
    end

    def input : String
      String.new(@input.to_slice)
    end

    def logical_module : String?
      @logical_module.try { |value| String.new(value.to_slice) }
    end

    def package : String?
      @package.try { |value| String.new(value.to_slice) }
    end

    def original_file : String?
      @original_file.try { |value| String.new(value.to_slice) }
    end

    def lexical_mode : String
      String.new(@lexical_mode.to_slice)
    end

    def input_sha256 : String
      String.new(@input_sha256.to_slice)
    end

    def warning_policy_json : String
      String.new(@warning_policy_json.to_slice)
    end

    def fresh_parser_contract : String
      String.new(@fresh_parser_contract.to_slice)
    end

    def warning_policy : WarningCollection::ParseAheadPolicy
      WarningCollection::ParseAheadPolicy.new(@warning_policy.level, @warning_policy.excluded_paths,
        @warning_policy.lib_path, @warning_policy.explain_spawn, @warning_policy.error_on_warnings?)
    end

    def scopes : Array(Array(String))
      @scopes.map { |scope| scope.map { |name| String.new(name.to_slice) } }
    end

    # This compares only the candidate's recorded fields, not the complete
    # parser contract, which must be checked separately before acceptance.
    def same_candidate?(other : AcceptedCaptureInput, source : String) : Bool
      @input == source && @input == other.stored_input &&
        @kind == other.kind && @logical_module == other.stored_logical_module &&
        @package == other.stored_package && @original_file == other.stored_original_file &&
        @lexical_mode == other.stored_lexical_mode && @entry == other.entry &&
        @mode == other.mode && @module_extends_written == other.module_extends_written &&
        @source_only == other.source_only && @visibility == other.visibility &&
        @def_nest == other.def_nest && @fun_nest == other.fun_nest &&
        @type_nest == other.type_nest && @wants_doc == other.wants_doc &&
        @scopes == other.stored_scopes && @warning_policy_json == other.stored_warning_policy_json &&
        @fresh_parser_contract == other.stored_fresh_parser_contract
    end

    def matches_source_token?(token : DiagnosticSourceNameToken) : Bool
      return false unless token.input_sha256 == @input_sha256 &&
                          token.input_bytesize == @input.bytesize &&
                          token.lexical_mode == @lexical_mode &&
                          token.input_start >= 0 && token.input_end <= @input.bytesize
      origin = token.lexical_origin.as?(DiagnosticOrigin::Written) || return false
      return false unless matches_written_identity?(origin)
      @input.to_slice[token.input_start, token.input_end - token.input_start] == token.raw_text.to_slice
    end

    def matches_written_identity?(origin : DiagnosticOrigin::Written) : Bool
      file = @original_file || return false
      return false unless origin.source_file == file
      return false unless origin.input_byte_offset >= 0 && origin.input_byte_offset <= @input.bytesize
      expected_module = @logical_module || "source-file:#{file}"
      origin.source_module == expected_module
    end

    def input_bytesize : Int32
      @input.bytesize
    end

    ENVELOPE_SCHEMA = "iyi-capture-envelope/1"
    CAPTURE_KEY_TAG = "iyi.capture.v1.key\0"
    MAX_ENVELOPE_INTEGER = 9007199254740991_i64

    # Canonical envelope (C1): keys sorted bytewise, no whitespace, ASCII only.
    # Every string is an identifier, lowercase hex or strict base64, and integers
    # are range-checked against 2^53 - 1 without taking an absolute value.
    def envelope_bytes : String
      entries = [] of {String, String}
      entries << {"schema", "\"#{ENVELOPE_SCHEMA}\""}
      entries << {"kind", envelope_identifier(@kind.to_s)}
      entries << {"entry", envelope_identifier(@entry.to_s)}
      entries << {"mode", envelope_identifier(@mode.to_s)}
      entries << {"lexical_mode", envelope_identifier(@lexical_mode)}
      entries << {"def_nest", envelope_integer(@def_nest.to_i64)}
      entries << {"fun_nest", envelope_integer(@fun_nest.to_i64)}
      entries << {"type_nest", envelope_integer(@type_nest.to_i64)}
      entries << {"module_extends_written", @module_extends_written.to_s}
      entries << {"source_only", @source_only.to_s}
      entries << {"wants_doc", @wants_doc.to_s}
      entries << {"visibility", @visibility.try { |value| envelope_identifier(value.to_s) } || "null"}
      entries << {"logical_module_b64", envelope_base64(@logical_module)}
      entries << {"package_b64", envelope_base64(@package)}
      entries << {"original_file_b64", envelope_base64(@original_file)}
      entries << {"scopes_b64", envelope_scopes}
      entries << {"fresh_parser_contract_b64", envelope_base64(@fresh_parser_contract)}
      entries << {"warning_policy_b64", envelope_base64(@warning_policy_json)}
      entries << {"context", "null"}
      members = entries.sort_by { |entry| entry[0] }.map { |key, value| "\"#{key}\":#{value}" }
      "{#{members.join(",")}}"
    end

    # Key = sha256("iyi.capture.v1.key\0" || envelope || "\0" || input_sha256 || "\0" || decimal(bytesize)).
    def capture_key : String
      material = String.build do |io|
        io << CAPTURE_KEY_TAG
        io << envelope_bytes
        io << "\0"
        io << @input_sha256
        io << "\0"
        io << @input.bytesize.to_s
      end
      ::Crystal::Digest::SHA256.hexdigest(material)
    end

    # Builds a fresh parser from this input alone: the recorded text, the decoded
    # contract and the rebuilt warning policy. Every field the contract records is
    # applied, so the replay runs in the live parser's own state. The caller
    # compares the replay's capture key with this one before any parse from it.
    def replay_parser : Parser
      fields = JSON.parse(@fresh_parser_contract).as_h
      scopes = fields["scopes"].as_a.map { |scope| Set(String).new(scope.as_a.map(&.as_s)) }
      warnings = WarningCollection.from_parse_ahead_snapshot(warning_policy)
      parser = Parser.new(@input, nil, scopes, warnings)
      filename = fields["filename"].as_s
      parser.filename = filename
      # The constructor requires a SourceFile's unit to equal its file, so the unit
      # is set unconditionally. Other kinds have no binding recipe yet.
      raise ArgumentError.new("EntryBuffer capture has no written identity rule") unless @kind.source_file?
      parser.diagnostic_source_file = filename
      parser.iyi = fields["lexical_mode"].as_s == "Iyi"
      parser.iyi_package_name = fields["package"].as_s?
      parser.iyi_source_only = fields["source_only"].as_bool
      parser.iyi_module_extends_written = fields["module_extends_written"].as_bool
      visibility = fields["visibility"].as_s?
      parser.visibility = visibility ? Visibility.parse(visibility) : nil
      parser.def_nest = fields["def_nest"].as_i
      parser.fun_nest = fields["fun_nest"].as_i
      parser.type_nest = fields["type_nest"].as_i
      parser.wants_doc = fields["wants_doc"].as_bool
      # After wants_doc, which overwrites doc_enabled.
      parser.doc_enabled = fields["doc_enabled"].as_bool
      parser.comments_enabled = fields["comments_enabled"].as_bool
      parser.count_whitespace = fields["count_whitespace"].as_bool
      parser.wants_raw = fields["wants_raw"].as_bool
      parser.slash_is_regex = fields["slash_is_regex"].as_bool
      parser.wants_regex = fields["wants_regex"].as_bool
      parser.wants_def_or_macro_name = fields["wants_def_or_macro_name"].as_bool
      parser.wants_symbol = fields["wants_symbol"].as_bool
      parser.iyi_reads_using = fields["reads_using"].as_bool
      parser.diagnostic_capture = true
      parser
    end

    # Captures the replay parser's own input, before it parses, for comparison.
    def replay_capture_input(parser : Parser) : AcceptedCaptureInput
      parser.diagnostic_capture_input(@kind, @logical_module, @entry, replay_parse_mode)
    end

    # The one executor the recorder and `bind!` share: the same entry and mode the
    # claim recorded. Only Parse is recordable, so any other entry has no executor.
    def replay_entry(parser : Parser) : ASTNode
      raise ArgumentError.new("capture entry has no executor") unless @entry.parse?
      parser.parse(replay_parse_mode)
    end

    private def replay_parse_mode : Parser::ParseMode
      case @mode
      when .normal?              then Parser::ParseMode::Normal
      when .lib?                 then Parser::ParseMode::Lib
      when .lib_struct_or_union? then Parser::ParseMode::LibStructOrUnion
      when .enum?                then Parser::ParseMode::Enum
      else                            raise ArgumentError.new("unmapped capture parse mode")
      end
    end

    private def envelope_identifier(value : String) : String
      raise ArgumentError.new("envelope value is not an identifier") unless value.matches?(/\A[A-Za-z_][A-Za-z0-9_]*\z/)
      "\"#{value}\""
    end

    private def envelope_integer(value : Int64) : String
      raise ArgumentError.new("envelope integer out of range") if value < -MAX_ENVELOPE_INTEGER || value > MAX_ENVELOPE_INTEGER
      value.to_s
    end

    private def envelope_base64(value : String?) : String
      return "null" unless value
      "\"#{Base64.strict_encode(value.to_slice)}\""
    end

    private def envelope_scopes : String
      rows = @scopes.map do |scope|
        names = scope.map { |name| "\"#{Base64.strict_encode(name.to_slice)}\"" }
        "[#{names.join(",")}]"
      end
      "[#{rows.join(",")}]"
    end

    def matches_encoded_span?(start_offset : Int32, end_offset : Int32, encoded : String) : Bool
      return false unless start_offset >= 0 && end_offset > start_offset && end_offset <= @input.bytesize
      return false if encoded.bytesize.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
      span = @input.to_slice[start_offset, end_offset - start_offset]
      return false if span.size.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64 * 3 // 4 - 4
      Base64.strict_encode(span) == encoded
    end

    private def validate_fresh_parser_contract! : Nil
      parser = JSON::Parser.new(@fresh_parser_contract)
      parser.max_nesting = 32
      parsed = parser.parse
      fields = parsed.as_h
      unless fields.keys == FRESH_CONTRACT_FIELDS && parsed.to_json == @fresh_parser_contract
        raise ArgumentError.new("noncanonical or unclassified fresh parser contract")
      end
      %w(package visibility).each do |field|
        value = fields[field].raw
        unless value.nil? || value.is_a?(String)
          raise ArgumentError.new("invalid nullable parser contract field #{field}")
        end
      end
      unless fields["entry_rule"].as_s == "parse" &&
             fields["filename"].as_s == @original_file &&
             fields["input_offset_base"].as_i == (@input.starts_with?('\uFEFF') ? 3 : 0) &&
             fields["lexical_mode"].as_s == @lexical_mode &&
             fields["package"].as_s? == @package &&
             fields["source_only"].as_bool == @source_only &&
             fields["module_extends_written"].as_bool == @module_extends_written &&
             fields["visibility"].as_s? == @visibility.try(&.to_s) &&
             fields["def_nest"].as_i == @def_nest && fields["fun_nest"].as_i == @fun_nest &&
             fields["type_nest"].as_i == @type_nest && fields["wants_doc"].as_bool == @wants_doc &&
             fields["diagnostic_capture"].as_bool && fields["lexical_journal_enabled"].as_bool
        raise ArgumentError.new("fresh parser contract disagrees with captured input state")
      end
      %w(reads_using doc_enabled comments_enabled count_whitespace wants_raw slash_is_regex wants_regex
         wants_def_or_macro_name wants_symbol).each { |field| fields[field].as_bool }
      source_unit = fields["source_unit"].raw
      raise ArgumentError.new("invalid parser source unit") unless source_unit.nil? || source_unit.is_a?(String)
      if @kind.source_file? && source_unit != "source-file:#{@original_file}"
        raise ArgumentError.new("source capture unit differs from its file")
      end
      scopes = fields["scopes"].as_a
      raise ArgumentError.new("fresh parser scope count mismatch") unless scopes.size == @scopes.size
      scopes.each_with_index do |scope, index|
        entries = scope.as_a
        expected = @scopes[index]
        raise ArgumentError.new("fresh parser scope mismatch") unless entries.size == expected.size
        entries.each_with_index do |entry, position|
          raise ArgumentError.new("fresh parser scope mismatch") unless entry.as_s == expected[position]
        end
      end
    end

    protected def stored_input : String
      @input
    end

    protected def stored_scopes : Array(Array(String))
      @scopes
    end

    protected def stored_logical_module : String?
      @logical_module
    end

    protected def stored_package : String?
      @package
    end

    protected def stored_original_file : String?
      @original_file
    end

    protected def stored_lexical_mode : String
      @lexical_mode
    end

    protected def stored_warning_policy_json : String
      @warning_policy_json
    end

    protected def stored_fresh_parser_contract : String
      @fresh_parser_contract
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

  # A value snapshot of the actual parser transition. It has no owner-graph
  # reference and therefore cannot serve as an adoption receipt or authority.
  class DiagnosticParseToDefEffectSnapshot
    @sha256 : String
    @bytes : String

    def initialize(effect : ParseToDefEffect)
      reset = ParseDefFlags.new(false, false, false, false, false)
      unless effect.delegated == reset && effect.delegated_block_arg_name.nil? && !effect.delegated_is_macro_def
        raise ArgumentError.new("parse_to_def did not reset delegated parser state")
      end
      unless effect.def_nest_before >= 0 && effect.def_nest_before < Int32::MAX &&
             effect.def_nest_after == effect.def_nest_before + 1
        raise ArgumentError.new("parse_to_def nesting transition mismatch")
      end
      raise ArgumentError.new("parse_to_def owner flags differ from parser result") unless effect.result == effect.owner_after
      output = DiagnosticCaptureOutput.new(DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64)
      json = JSON::Builder.new(output)
      json.start_document
      json.object do
        json.field("owner_before") { write_flags(json, effect.owner_before) }
        json.field("delegated") { write_flags(json, effect.delegated) }
        json.field "delegated_block_arg_name", effect.delegated_block_arg_name
        json.field "delegated_is_macro_def", effect.delegated_is_macro_def
        json.field("result") { write_flags(json, effect.result) }
        json.field("owner_after") { write_flags(json, effect.owner_after) }
        json.field "def_nest_before", effect.def_nest_before
        json.field "def_nest_after", effect.def_nest_after
      end
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      String.new(@bytes.to_slice)
    end

    def sha256 : String
      String.new(@sha256.to_slice)
    end

    private def write_flags(json : JSON::Builder, flags : ParseDefFlags) : Nil
      json.object do
        json.field "calls_super", flags.calls_super
        json.field "calls_initialize", flags.calls_initialize
        json.field "calls_previous_def", flags.calls_previous_def
        json.field "uses_block_arg", flags.uses_block_arg
        json.field "assigns_special_var", flags.assigns_special_var
      end
    end
  end

  # Frozen ordered pragma input, not an authenticated parse or registry.
  class DiagnosticPragmaSnapshot
    MAX_BYTES = 64_i64 * 1024 * 1024
    @sha256 : String
    @bytes : String
    @graph_budget : UInt64 = DiagnosticOrigin::MAX_UNFOLDED_BYTES

    def initialize(pragmas : Hash(Int32, Array(Lexer::LocPragma))?)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
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
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      String.new(@bytes.to_slice)
    end

    def sha256 : String
      String.new(@sha256.to_slice)
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

    # Canonical decode of snapshot bytes into the live pragma structure. Insertion
    # order is kept exactly, and a repeated offset is refused. Every value is
    # rebuilt with the public constructor of its own type. Origins come from
    # DiagnosticOrigin.from_json under one budget shared by the whole snapshot.
    # The canonical round trip at the end proves that each rebuilt value writes
    # back the same bytes, so anything that does not reconstruct exactly is refused.
    def self.read(bytes : String) : Hash(Int32, Array(Lexer::LocPragma))?
      raise ArgumentError.new("pragma snapshot exceeds size limit") if bytes.bytesize.to_i64 > MAX_BYTES
      raise ArgumentError.new("pragma snapshot is not UTF-8") unless bytes.valid_encoding?
      tree = begin
        JSON.parse(bytes)
      rescue ex : JSON::ParseException
        raise ArgumentError.new("pragma snapshot is not parseable JSON: #{ex.message}")
      end
      top = pragma_fields!(tree, %w(present entries), "snapshot")
      present_value = top["present"].raw
      raise ArgumentError.new("pragma snapshot present is not a boolean") unless present_value.is_a?(Bool)
      present = present_value
      entries = pragma_array!(top["entries"], "entries")
      raise ArgumentError.new("pragma snapshot has entries but is not present") if !present && !entries.empty?
      decoded : Hash(Int32, Array(Lexer::LocPragma))? = nil
      if present
        budget = DiagnosticOrigin::DecodeBudget.new
        result = {} of Int32 => Array(Lexer::LocPragma)
        entries.each do |entry|
          item = pragma_fields!(entry, %w(offset pragmas), "entry")
          offset = pragma_integer!(item["offset"], "offset")
          raise ArgumentError.new("pragma offset is negative") if offset < 0
          raise ArgumentError.new("pragma snapshot repeats offset #{offset}") if result.has_key?(offset)
          result[offset] = pragma_array!(item["pragmas"], "pragmas").map { |pragma| decode_pragma(pragma, budget) }
        end
        decoded = result
      end
      raise ArgumentError.new("pragma snapshot is not in canonical encoding") unless DiagnosticPragmaSnapshot.new(decoded).bytes == bytes
      decoded
    end

    private def self.decode_pragma(pragma : JSON::Any, budget : DiagnosticOrigin::DecodeBudget) : Lexer::LocPragma
      case kind = pragma_kind!(pragma)
      when "Set"
        item = pragma_fields!(pragma, %w(kind filename line column artifact), "Set pragma")
        Lexer::LocSetPragma.new(pragma_text!(item["filename"], "filename"), pragma_integer!(item["line"], "line"),
          pragma_integer!(item["column"], "column"), pragma_nullable_text!(item["artifact"], "artifact"))
      when "Push"
        pragma_fields!(pragma, %w(kind), "Push pragma")
        Lexer::LocPushPragma.new
      when "Pop"
        pragma_fields!(pragma, %w(kind), "Pop pragma")
        Lexer::LocPopPragma.new
      when "Origin"
        item = pragma_fields!(pragma, %w(kind line), "Origin pragma")
        Lexer::LocOriginPragma.new(pragma_integer!(item["line"], "line"))
      when "DiagnosticEmission"
        emission_from_json!(pragma, budget, 0)
      else
        raise ArgumentError.new("unknown pragma kind #{kind}")
      end
    end

    private def self.pragma_fields!(value : JSON::Any, keys : Array(String), where : String) : Hash(String, JSON::Any)
      hash = value.as_h? || raise ArgumentError.new("pragma #{where} is not an object")
      raise ArgumentError.new("pragma #{where} keys are not #{keys.join(", ")}") unless hash.keys == keys
      hash
    end

    private def self.pragma_kind!(value : JSON::Any) : String
      hash = value.as_h? || raise ArgumentError.new("pragma is not an object")
      pragma_text!(hash["kind"]? || raise(ArgumentError.new("pragma lacks kind")), "kind")
    end

    private def self.pragma_array!(value : JSON::Any, where : String) : Array(JSON::Any)
      value.as_a? || raise ArgumentError.new("pragma #{where} is not an array")
    end

    private def self.pragma_text!(value : JSON::Any, where : String) : String
      value.raw.as?(String) || raise ArgumentError.new("pragma #{where} is not a string")
    end

    private def self.pragma_nullable_text!(value : JSON::Any, where : String) : String?
      return nil if value.raw.nil?
      pragma_text!(value, where)
    end

    private def self.pragma_integer!(value : JSON::Any, where : String) : Int32
      number = value.raw.as?(Int64) || raise ArgumentError.new("pragma #{where} is not an integer")
      raise ArgumentError.new("pragma #{where} is out of range") if number < Int32::MIN || number > Int32::MAX
      number.to_i32
    end

    # Typed emission readers. Each rebuilds one value from its canonical JSON with
    # the public constructor of its own type. Enumerations accept exact member names
    # only, and nesting is bounded by check_depth!. A value that does not write back
    # to the same bytes is refused by the canonical round trip in `read`.
    private def self.check_depth!(depth : Int32) : Nil
      raise ArgumentError.new("pragma nesting is too deep") if depth > DiagnosticOrigin::MAX_DEPTH
    end

    private def self.emission_from_json!(pragma : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : Lexer::LocDiagnosticEmission
      check_depth!(depth)
      item = pragma_fields!(pragma, %w(kind end claims generated_text name_fragments), "DiagnosticEmission pragma")
      Lexer::LocDiagnosticEmission.new(
        pragma_integer!(item["end"], "emission end"),
        pragma_array!(item["claims"], "claims").map { |claim| claim_from_json!(claim, budget, depth + 1) },
        pragma_array!(item["generated_text"], "generated_text").map { |text| generated_text_from_json!(text, budget, depth + 1) },
        pragma_array!(item["name_fragments"], "name_fragments").map { |fragment| name_fragment_from_json!(fragment, budget, depth + 1) })
    end

    private def self.origin_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget) : DiagnosticOrigin
      DiagnosticOrigin.from_json(value, 0, budget)
    end

    private def self.optional_origin_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget) : DiagnosticOrigin?
      return nil if value.raw.nil?
      origin_from_json!(value, budget)
    end

    private def self.writer_from_json!(value : JSON::Any, where : String) : DiagnosticWriterRef
      item = pragma_fields!(value, %w(start end), where)
      start = pragma_integer!(item["start"], "#{where} start")
      finish = pragma_integer!(item["end"], "#{where} end")
      raise ArgumentError.new("pragma #{where} ends before it starts") if start < 0 || finish < start
      DiagnosticWriterRef.new(start, finish)
    end

    private def self.key_from_json!(value : JSON::Any, where : String) : DiagnosticMacroClaimKey
      item = pragma_fields!(value, %w(writer kind role), where)
      DiagnosticMacroClaimKey.new(writer_from_json!(item["writer"], "#{where} writer"),
        pragma_text!(item["kind"], "#{where} kind"), pragma_text!(item["role"], "#{where} role"))
    end

    private def self.producer_from_json!(value : JSON::Any) : DiagnosticMacroProducer
      text = pragma_text!(value, "producer")
      DiagnosticMacroProducer.parse?(text) || raise ArgumentError.new("unknown macro producer #{text}")
    end

    private def self.evidence_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticAnchorEvidence
      check_depth!(depth)
      case kind = pragma_kind!(value)
      when "Spliced"
        item = pragma_fields!(value, %w(kind source_origin), "Spliced evidence")
        DiagnosticAnchorEvidence::Spliced.new(origin_from_json!(item["source_origin"], budget))
      when "Constructed"
        item = pragma_fields!(value, %w(kind producer), "Constructed evidence")
        DiagnosticAnchorEvidence::Constructed.new(producer_from_json!(item["producer"]))
      when "RawSyntax"
        item = pragma_fields!(value, %w(kind witnesses), "RawSyntax evidence")
        DiagnosticAnchorEvidence::RawSyntax.new(pragma_array!(item["witnesses"], "witnesses").map { |witness| witness_from_json!(witness, budget, depth + 1) })
      when "DerivedFromOwner"
        pragma_fields!(value, %w(kind), "DerivedFromOwner evidence")
        DiagnosticAnchorEvidence::DerivedFromOwner.new
      else
        raise ArgumentError.new("unknown evidence kind #{kind}")
      end
    end

    private def self.witness_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticSyntaxWitness
      check_depth!(depth)
      item = pragma_fields!(value, %w(role event), "syntax witness")
      text = pragma_text!(item["role"], "witness role")
      role = DiagnosticWitnessRole.parse?(text) || raise ArgumentError.new("unknown witness role #{text}")
      DiagnosticSyntaxWitness.new(role, token_event_from_json!(item["event"], budget, depth + 1))
    end

    private def self.token_event_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticTokenEvent
      check_depth!(depth)
      item = pragma_fields!(value, %w(input_start input_end token_kind token_text lexical_mode selection byte_parts), "token event")
      text = pragma_text!(item["selection"], "selection")
      selection = DiagnosticTokenSelection.parse?(text) || raise ArgumentError.new("unknown token selection #{text}")
      DiagnosticTokenEvent.new(pragma_integer!(item["input_start"], "token input start"),
        pragma_integer!(item["input_end"], "token input end"), pragma_text!(item["token_kind"], "token kind"),
        pragma_text!(item["token_text"], "token text"), pragma_text!(item["lexical_mode"], "token lexical mode"), selection,
        pragma_array!(item["byte_parts"], "byte_parts").map { |part| emission_part_from_json!(part, budget, depth + 1) })
    end

    private def self.emission_part_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticEmissionPart
      check_depth!(depth)
      case kind = pragma_kind!(value)
      when "Generated"
        item = pragma_fields!(value, %w(kind start_offset end_offset emitter_origin producer), "Generated part")
        DiagnosticEmissionPart::Generated.new(pragma_integer!(item["start_offset"], "part start"),
          pragma_integer!(item["end_offset"], "part end"), optional_origin_from_json!(item["emitter_origin"], budget),
          producer_from_json!(item["producer"]))
      when "AstAnchor"
        item = pragma_fields!(value, %w(kind start_offset end_offset emitter_origin source_origin), "AstAnchor part")
        DiagnosticEmissionPart::AstAnchor.new(pragma_integer!(item["start_offset"], "part start"),
          pragma_integer!(item["end_offset"], "part end"), optional_origin_from_json!(item["emitter_origin"], budget),
          origin_from_json!(item["source_origin"], budget))
      when "NameSplice"
        item = pragma_fields!(value, %w(kind start_offset end_offset emitter_origin source_name), "NameSplice part")
        DiagnosticEmissionPart::NameSplice.new(pragma_integer!(item["start_offset"], "part start"),
          pragma_integer!(item["end_offset"], "part end"), optional_origin_from_json!(item["emitter_origin"], budget),
          name_value_from_json!(item["source_name"], budget, depth + 1))
      else
        raise ArgumentError.new("unknown emission part kind #{kind}")
      end
    end

    private def self.name_value_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticNameValue
      check_depth!(depth)
      case kind = pragma_kind!(value)
      when "Observed"
        item = pragma_fields!(value, %w(kind source_token), "Observed name")
        DiagnosticNameValue::Observed.new(source_token_from_json!(item["source_token"], budget, depth + 1))
      when "Derived"
        item = pragma_fields!(value, %w(kind origin), "Derived name")
        origin = origin_from_json!(item["origin"], budget)
        DiagnosticNameValue::Derived.new(origin.as?(DiagnosticOrigin::DerivedName) || raise ArgumentError.new("derived name value lacks a derived origin"))
      else
        raise ArgumentError.new("unknown name value kind #{kind}")
      end
    end

    private def self.source_token_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticSourceNameToken
      check_depth!(depth)
      item = pragma_fields!(value, %w(lexical_origin binding_origin context input_sha256 input_bytesize input_start input_end lexical_mode token_kind raw_text), "source token")
      DiagnosticSourceNameToken.new(origin_from_json!(item["lexical_origin"], budget),
        optional_origin_from_json!(item["binding_origin"], budget), pragma_text!(item["context"], "token context"),
        pragma_text!(item["input_sha256"], "token input digest"), pragma_integer!(item["input_bytesize"], "token input bytesize"),
        pragma_integer!(item["input_start"], "token input start"), pragma_integer!(item["input_end"], "token input end"),
        pragma_text!(item["lexical_mode"], "token lexical mode"), pragma_text!(item["token_kind"], "token kind"),
        pragma_text!(item["raw_text"], "token raw text"))
    end

    private def self.claim_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticMacroClaim
      check_depth!(depth)
      item = pragma_fields!(value, %w(key evidence attachment emitter_origin), "claim")
      DiagnosticMacroClaim.new(key_from_json!(item["key"], "claim key"),
        evidence_from_json!(item["evidence"], budget, depth + 1),
        attachment_from_json!(item["attachment"]),
        optional_origin_from_json!(item["emitter_origin"], budget))
    end

    private def self.attachment_from_json!(value : JSON::Any) : DiagnosticMacroAttachment
      case kind = pragma_kind!(value)
      when "Direct"
        item = pragma_fields!(value, %w(kind writer), "Direct attachment")
        DiagnosticMacroAttachment::Direct.new(writer_from_json!(item["writer"], "attachment writer"))
      when "HeadOf"
        item = pragma_fields!(value, %w(kind rule head), "HeadOf attachment")
        text = pragma_text!(item["rule"], "head rule")
        rule = DiagnosticHeadRule.parse?(text) || raise ArgumentError.new("unknown head rule #{text}")
        DiagnosticMacroAttachment::HeadOf.new(rule, head_from_json!(item["head"]))
      when "PayloadOf"
        item = pragma_fields!(value, %w(kind rule owner_key), "PayloadOf attachment")
        text = pragma_text!(item["rule"], "payload rule")
        rule = DiagnosticPayloadRule.parse?(text) || raise ArgumentError.new("unknown payload rule #{text}")
        DiagnosticMacroAttachment::PayloadOf.new(rule, key_from_json!(item["owner_key"], "owner key"))
      else
        raise ArgumentError.new("unknown attachment kind #{kind}")
      end
    end

    private def self.head_from_json!(value : JSON::Any) : DiagnosticMacroHead
      case kind = pragma_kind!(value)
      when "Anchor"
        item = pragma_fields!(value, %w(kind writer), "Anchor head")
        DiagnosticMacroHead::Anchor.new(writer_from_json!(item["writer"], "head writer"))
      when "Syntax"
        item = pragma_fields!(value, %w(kind form writer adjacent_name_writer), "Syntax head")
        text = pragma_text!(item["form"], "head form")
        form = DiagnosticHeadSyntax.parse?(text) || raise ArgumentError.new("unknown head syntax #{text}")
        adjacent = item["adjacent_name_writer"].raw.nil? ? nil : writer_from_json!(item["adjacent_name_writer"], "adjacent writer")
        DiagnosticMacroHead::Syntax.new(form, writer_from_json!(item["writer"], "head writer"), adjacent)
      else
        raise ArgumentError.new("unknown head kind #{kind}")
      end
    end

    private def self.generated_text_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticGeneratedText
      check_depth!(depth)
      item = pragma_fields!(value, %w(start end emitter_origin producer), "generated text")
      DiagnosticGeneratedText.new(pragma_integer!(item["start"], "generated start"), pragma_integer!(item["end"], "generated end"),
        optional_origin_from_json!(item["emitter_origin"], budget), producer_from_json!(item["producer"]))
    end

    private def self.name_fragment_from_json!(value : JSON::Any, budget : DiagnosticOrigin::DecodeBudget, depth : Int32) : DiagnosticMacroNameFragment
      check_depth!(depth)
      item = pragma_fields!(value, %w(start end emitter_origin source_name), "name fragment")
      DiagnosticMacroNameFragment.new(pragma_integer!(item["start"], "fragment start"), pragma_integer!(item["end"], "fragment end"),
        optional_origin_from_json!(item["emitter_origin"], budget), name_value_from_json!(item["source_name"], budget, depth + 1))
    end
  end

  # A structural filename snapshot, not a resolved authority graph. Macro
  # owners must already have a capture coordinate; this does not assert that
  # the coordinate resolves in a separately trusted registry.
  class DiagnosticFilenameSnapshot
    MAX_BYTES = 8_i64 * 1024 * 1024
    MAX_DEPTH = 128
    @sha256 : String
    @bytes : String
    @seen = Set(UInt64).new

    def initialize(filename : String | VirtualFile | Nil)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      write_filename(json, filename, 0)
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      String.new(@bytes.to_slice)
    end

    def sha256 : String
      String.new(@sha256.to_slice)
    end

    # Read-only view of the stored bytes, for a single emission. It is not retained.
    def bytes_slice : Bytes
      @bytes.to_slice
    end

    private def write_ref(json : JSON::Builder, ref : DiagnosticCaptureFieldRef) : Nil
      json.object do
        json.field "capture_id", ref.capture_id
        json.field "owner_path_json", ref.owner_path_json
        json.field "field_tag", ref.field_tag
        json.field "index", ref.index
        key = ref.map_key
        if key && key.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
          raise ArgumentError.new("filename owner map key exceeds size limit")
        end
        json.field "map_key_base64", key.try { |value| Base64.strict_encode(value.to_slice) }
      end
    end

    private def write_filename(json : JSON::Builder, filename : String | VirtualFile | Nil, depth : Int32) : Nil
      raise ArgumentError.new("filename graph exceeds depth limit") if depth > MAX_DEPTH
      json.object do
        case filename
        when Nil
          json.field "kind", "Absent"
        when String
          json.field "kind", "SourceFile"
          json.field "original_file", filename
        when VirtualFile
          id = filename.object_id
          raise ArgumentError.new("cyclic virtual filename") unless @seen.add?(id)
          begin
            owner = filename.macro.diagnostic_capture_ref || raise ArgumentError.new("virtual filename macro lacks capture reference")
            source = filename.source
            raise ArgumentError.new("virtual filename input exceeds size limit") if source.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
            json.field "kind", "VirtualFile"
            json.field "input_base64", Base64.strict_encode(source.to_slice)
            json.field "input_sha256", ::Crystal::Digest::SHA256.hexdigest(source)
            json.field("macro_owner") { write_ref(json, owner) }
            json.field "depth", filename.depth
            json.field "line_origins" do
              if origins = filename.line_origins
                json.array do
                  origins.each do |line, origin|
                    json.array { json.number(line); json.number(origin) }
                  end
                end
              else
                json.null
              end
            end
            json.field "expanded_location" do
              if location = filename.expanded_location
                json.object do
                  json.field "line", location.line_number
                  json.field "column", location.column_number
                  json.field "artifact", location.artifact
                  json.field("filename") { write_filename(json, location.filename, depth + 1) }
                end
              else
                json.null
              end
            end
          ensure
            @seen.delete(id)
          end
        else
          raise ArgumentError.new("unclassified filename binding")
        end
      end
    end
  end

  # Reads every Path.names element directly. This snapshot is an incremental
  # field encoder, not a complete AST census or a registry authority.
  class DiagnosticPathSnapshot
    @sha256 : String
    @bytes : String

    def initialize(path : Path, input : AcceptedCaptureInput)
      DiagnosticAstFieldSchema.validate_reflected_fields(path)
      names = path.names
      raise ArgumentError.new("path has no name segments") if names.empty?
      raise ArgumentError.new("path name inventory exceeds size limit") if names.size.to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64 // 64
      if path.diagnostic_name_slots_count != names.size ||
         path.diagnostic_name_slots_graph_bytes > DiagnosticOrigin::MAX_UNFOLDED_BYTES
        raise ArgumentError.new("path name evidence does not cover all segments or exceeds the graph limit")
      end
      slots = Array(Indexable(DiagnosticNameValue)?).new(names.size, nil)
      path.each_diagnostic_name_slot do |slot, values|
        unless slot.kind.path_segment? && slot.index < names.size && slots[slot.index].nil?
          raise ArgumentError.new("invalid path name evidence slot")
        end
        slots[slot.index] = values
      end
      origin = path.diagnostic_origin || raise ArgumentError.new("path lacks structural origin")
      raise ArgumentError.new("path origin exceeds depth limit") if origin.graph_depth > DiagnosticOrigin::MAX_DEPTH
      budget = DiagnosticOrigin::MAX_UNFOLDED_BYTES
      raise ArgumentError.new("path origin exceeds size limit") if origin.graph_bytes > budget
      budget -= origin.graph_bytes
      output = DiagnosticCaptureOutput.new(DiagnosticPragmaSnapshot::MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      json.object do
        json.field "node_kind", "Path"
        json.field "names" do
          json.array do
            names.each_with_index do |name, index|
              values = slots[index] ||
                       raise ArgumentError.new("missing path segment evidence at #{index}")
              raise ArgumentError.new("ambiguous path segment evidence at #{index}") unless values.size == 1
              value = values.first
              raise ArgumentError.new("path segment evidence differs at #{index}") unless value.rendered_text == name
              raise ArgumentError.new("path name evidence exceeds size limit") if value.graph_bytes > budget
              budget -= value.graph_bytes
              if value.is_a?(DiagnosticNameValue::Observed)
                token = value.source_token
                unless input.matches_source_token?(token)
                  raise ArgumentError.new("path segment evidence input mismatch at #{index}")
                end
              elsif !value.is_a?(DiagnosticNameValue::Derived)
                raise ArgumentError.new("unclassified path name evidence")
              end
              json.object do
                json.field "index", index
                json.field "value", name
                json.field "evidence", value
              end
            end
          end
        end
        json.field "global", path.global?
        json.field "visibility", path.visibility.to_s
        json.field "exported", path.exported?
        json.field "iyi_from_artifact", path.iyi_from_artifact?
        json.field "iyi_synthetic", path.iyi_synthetic?
        json.field("location") { write_location(json, path.diagnostic_stored_location) }
        json.field("end_location") { write_location(json, path.diagnostic_stored_end_location) }
        json.field "origin", origin
        json.field "macro_lineage", path.diagnostic_macro_lineage.to_s
      end
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      String.new(@bytes.to_slice)
    end

    def sha256 : String
      String.new(@sha256.to_slice)
    end

    private def write_location(json : JSON::Builder, location : Location?) : Nil
      unless location
        json.null
        return
      end
      filename = DiagnosticFilenameSnapshot.new(location.filename)
      json.object do
        json.field "filename_snapshot", filename.bytes
        json.field "line", location.line_number
        json.field "column", location.column_number
        json.field "artifact", location.artifact
      end
    end
  end

  enum DiagnosticAstFieldClass
    Child
    ChildList
    NamedValue
    NamedChildMap
    IndexedChildMap
    Record
    RecordList
    SyntaxScalar
    OriginEvidence
    Infrastructure
  end

  # Closed incremental classification. Unknown kinds and fields are errors;
  # the entries here do not claim that the complete syntax schema is present.
  module DiagnosticAstFieldSchema
    SUPPORTED = %w(Path Generic Union TypeOf Arg NamedArgument Def Nop NilLiteral ImplicitObj Self Underscore
      Expressions BoolLiteral NumberLiteral CharLiteral StringLiteral SymbolLiteral MacroLiteral
      StringInterpolation ArrayLiteral TupleLiteral RangeLiteral RegexLiteral Var InstanceVar ClassVar
      Global ReadInstanceVar If Unless Assign OpAssign MultiAssign And Or ProcNotation HashLiteral NamedTupleLiteral
      Block Call Macro Not PointerOf SizeOf InstanceSizeOf AlignOf InstanceAlignOf Out MacroVerbatim Splat DoubleSplat
      OffsetOf VisibilityModifier IsA RespondsTo Require When Case Select While Until Rescue ExceptionHandler
      Return Break Next Yield ClassDef TraitDef Propagate Defer Recover AssocTypeDecl ImplDef ModuleHeader
      ImportDecl UsingDecl ModuleDef AnnotationDef TypeDeclaration UninitializedVar ProcLiteral ProcPointer
      Include Extend LibDef FunDef TypeDef CStructOrUnionDef EnumDef ExternalVar Alias Metaclass Cast NilableCast
      Annotation MacroExpression MacroIf MacroFor MacroVar MagicConstant Asm AsmOperand)

    def self.classify(kind : String, field : String) : DiagnosticAstFieldClass
      case field
      when "location", "end_location", "diagnostic_origin", "diagnostic_macro_lineage",
           "diagnostic_name_slots", "diagnostic_literal_names", "diagnostic_literal_productions"
        return DiagnosticAstFieldClass::OriginEvidence if SUPPORTED.includes?(kind)
      when "diagnostic_external_explicit"
        return DiagnosticAstFieldClass::OriginEvidence if kind == "Arg"
        return DiagnosticAstFieldClass::Infrastructure if SUPPORTED.includes?(kind)
      when "diagnostic_capture_ref", "diagnostic_percent_witnesses"
        return DiagnosticAstFieldClass::Infrastructure if SUPPORTED.includes?(kind)
      when "dependencies", "observers", "enclosing_call", "dirty", "type"
        return DiagnosticAstFieldClass::Infrastructure if SUPPORTED.includes?(kind)
      end
      if rows = DiagnosticFieldTable::TABLE[kind]?
        if row = rows.find { |item| item.field == field && item.provenance.semantic? }
          return row.klass
        end
      end
      case kind
      when "Path"
        return DiagnosticAstFieldClass::NamedValue if field == "names"
        return DiagnosticAstFieldClass::SyntaxScalar if {"global", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if {"iyi_from_artifact", "iyi_synthetic", "target_const", "target_type", "syntax_replacement"}.includes?(field)
      when "Generic"
        return DiagnosticAstFieldClass::Child if field == "name"
        return DiagnosticAstFieldClass::ChildList if {"type_vars", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "suffix"
        return DiagnosticAstFieldClass::Infrastructure if {"instance_type", "scope", "in_type_args", "inside_is_a"}.includes?(field)
      when "Union"
        return DiagnosticAstFieldClass::ChildList if field == "types"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "parens"
        return DiagnosticAstFieldClass::Infrastructure if field == "inside_is_a"
      when "TypeOf"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
        return DiagnosticAstFieldClass::Infrastructure if field == "in_type_args"
      when "Arg"
        return DiagnosticAstFieldClass::NamedValue if {"name", "external_name"}.includes?(field)
        return DiagnosticAstFieldClass::Child if {"default_value", "restriction"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "parsed_annotations"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
        return DiagnosticAstFieldClass::Infrastructure if {"annotations", "original_name"}.includes?(field)
      when "NamedArgument"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "value"
      when "Def"
        return DiagnosticAstFieldClass::NamedValue if {"name", "free_vars"}.includes?(field)
        return DiagnosticAstFieldClass::NamedChildMap if {"free_var_bounds", "where_bounds"}.includes?(field)
        return DiagnosticAstFieldClass::Child if {"receiver", "double_splat", "body", "block_arg", "return_type"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
        return DiagnosticAstFieldClass::SyntaxScalar if {"block_arity", "splat_index", "doc", "visibility", "exported",
          "iyi_from_impl", "macro_def", "abstract", "calls_super", "calls_initialize", "calls_previous_def",
          "uses_block_arg", "assigns_special_var"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if {"annotations", "owner", "original_owner", "vars", "yield_vars",
          "previous", "next", "special_vars", "freeze_type", "block_nest", "raises", "closure", "self_closured",
          "captured_block", "no_inline", "always_inline", "returns_twice", "target_features", "target_cpu", "naked",
          "new", "original_name", "macro_owner", "self_restriction_type", "iyi_declared_return", "iyi_from_artifact",
          "iyi_body_travelled", "iyi_compiler_made", "iyi_origin", "diagnostic_specialization_json",
          "diagnostic_specialization_unusable", "iyi_open_travel", "iyi_defer", "iyi_from_derive", "iyi_share_block",
          "iyi_observer_wrapped", "effect", "iyi_share_serial", "iyi_share_crossing", "iyi_share_elements",
          "diagnostic_proc_node", "diagnostic_proc_parent", "diagnostic_proc_lexical_scope",
          "diagnostic_proc_ready", "diagnostic_proc_computing"}.includes?(field)
      when "Expressions"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "keyword"
      when "BoolLiteral", "CharLiteral", "StringLiteral", "MacroLiteral"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "value"
      when "SymbolLiteral"
        return DiagnosticAstFieldClass::NamedValue if field == "value"
      when "NumberLiteral"
        return DiagnosticAstFieldClass::SyntaxScalar if {"value", "kind"}.includes?(field)
      when "StringInterpolation"
        return DiagnosticAstFieldClass::ChildList if field == "expressions"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "heredoc_indent"
      when "ArrayLiteral"
        return DiagnosticAstFieldClass::ChildList if field == "elements"
        return DiagnosticAstFieldClass::Child if {"of", "name"}.includes?(field)
      when "TupleLiteral"
        return DiagnosticAstFieldClass::ChildList if field == "elements"
        return DiagnosticAstFieldClass::Infrastructure if field == "program"
      when "RangeLiteral"
        return DiagnosticAstFieldClass::Child if {"from", "to"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "exclusive"
      when "RegexLiteral"
        return DiagnosticAstFieldClass::Child if field == "value"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "options"
      when "Var", "InstanceVar", "ClassVar", "Global"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "Var" && field == "doc"
        return DiagnosticAstFieldClass::Infrastructure if {"ClassVar", "Global"}.includes?(kind) && field == "var"
      when "ReadInstanceVar"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "If", "Unless"
        return DiagnosticAstFieldClass::Child if {"cond", "then", "else"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "else_location"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "If" && field == "ternary"
        return DiagnosticAstFieldClass::Infrastructure if kind == "If" && field == "iyi_definition_probe"
        return DiagnosticAstFieldClass::Infrastructure if kind == "If" && {"and", "or", "truthy", "falsey"}.includes?(field)
      when "Assign"
        return DiagnosticAstFieldClass::Child if {"target", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
        return DiagnosticAstFieldClass::Infrastructure if field == "discarded"
      when "OpAssign"
        return DiagnosticAstFieldClass::Child if {"target", "value"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "op"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "MultiAssign"
        return DiagnosticAstFieldClass::ChildList if {"targets", "values"}.includes?(field)
      when "And", "Or"
        return DiagnosticAstFieldClass::Child if {"left", "right"}.includes?(field)
      when "ProcNotation"
        return DiagnosticAstFieldClass::ChildList if field == "inputs"
        return DiagnosticAstFieldClass::Child if field == "output"
      when "HashLiteral"
        return DiagnosticAstFieldClass::RecordList if field == "entries"
        return DiagnosticAstFieldClass::Record if field == "of"
        return DiagnosticAstFieldClass::Child if field == "name"
      when "NamedTupleLiteral"
        return DiagnosticAstFieldClass::RecordList if field == "entries"
        return DiagnosticAstFieldClass::Infrastructure if field == "program"
      when "HashLiteral::Entry"
        return DiagnosticAstFieldClass::Child if {"key", "value"}.includes?(field)
      when "NamedTupleLiteral::Entry"
        return DiagnosticAstFieldClass::NamedValue if field == "key"
        return DiagnosticAstFieldClass::Child if field == "value"
      when "Block"
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "splat_index"
        return DiagnosticAstFieldClass::IndexedChildMap if field == "unpacks"
        return DiagnosticAstFieldClass::Infrastructure if {"call", "diagnostic_specialization_json",
          "diagnostic_specialization_unusable", "scope", "vars", "after_vars", "context", "fun_literal",
          "freeze_type", "visited", "break"}.includes?(field)
      when "Call"
        return DiagnosticAstFieldClass::Child if {"obj", "block", "block_arg"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if {"args", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "global", "expansion", "args_in_brackets",
          "has_parentheses", "iyi_group", "iyi_banged"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if field == "before_vars"
        return DiagnosticAstFieldClass::OriginEvidence if {"name_location", "iyi_after_floor_div"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if {"name_size", "iyi_synthetic", "iyi_compiler_expansion", "iyi_open_dispatch"}.includes?(field)
      when "Macro"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if {"body", "double_splat", "block_arg"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::SyntaxScalar if {"splat_index", "doc", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
        return DiagnosticAstFieldClass::Infrastructure if {"annotations", "owner"}.includes?(field)
      when "Not", "PointerOf", "SizeOf", "InstanceSizeOf", "AlignOf", "InstanceAlignOf", "Out",
           "MacroVerbatim", "Splat", "DoubleSplat", "Propagate", "Defer", "Return", "Break", "Next"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::Infrastructure if kind == "Return" && field == "from_propagate"
      when "OffsetOf"
        return DiagnosticAstFieldClass::Child if {"offsetof_type", "offset"}.includes?(field)
      when "VisibilityModifier"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::SyntaxScalar if {"modifier", "doc"}.includes?(field)
      when "IsA"
        return DiagnosticAstFieldClass::Child if {"obj", "const"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"nil_check", "error_construct", "iyi_bang_call"}.includes?(field)
      when "RespondsTo"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "Require"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "string"
        return DiagnosticAstFieldClass::Infrastructure if field == "iyi_prelude"
      when "When"
        return DiagnosticAstFieldClass::ChildList if field == "conds"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "exhaustive"
      when "Case"
        return DiagnosticAstFieldClass::Child if {"cond", "else"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "whens"
        return DiagnosticAstFieldClass::SyntaxScalar if {"exhaustive", "binds_it"}.includes?(field)
      when "Select"
        return DiagnosticAstFieldClass::ChildList if field == "whens"
        return DiagnosticAstFieldClass::Child if field == "else"
      when "While", "Until"
        return DiagnosticAstFieldClass::Child if {"cond", "body"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if kind == "While" && field == "break_vars"
      when "Rescue"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::ChildList if field == "types"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
      when "ExceptionHandler"
        return DiagnosticAstFieldClass::Child if {"body", "else", "ensure"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "rescues"
        return DiagnosticAstFieldClass::SyntaxScalar if {"implicit", "suffix"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if {"else_location", "ensure_location"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if field == "iyi_defer"
      when "Yield"
        return DiagnosticAstFieldClass::ChildList if field == "exps"
        return DiagnosticAstFieldClass::Child if field == "scope"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "has_parentheses"
        return DiagnosticAstFieldClass::Infrastructure if field == "expanded"
      when "ClassDef"
        return DiagnosticAstFieldClass::Child if {"name", "body", "superclass"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "splat_index", "abstract", "struct", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "TraitDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "supertraits"
        return DiagnosticAstFieldClass::NamedValue if {"type_vars", "assoc_types"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "Recover"
        return DiagnosticAstFieldClass::Child if {"exp", "default"}.includes?(field)
      when "AssocTypeDecl"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "value"
        return DiagnosticAstFieldClass::SyntaxScalar if {"in_type_body", "doc"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "ImplDef"
        return DiagnosticAstFieldClass::Child if {"trait", "target", "body"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "trait_args"
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::NamedChildMap if {"type_var_bounds", "assoc_types"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "ModuleHeader"
        return DiagnosticAstFieldClass::NamedValue if field == "path"
      when "ImportDecl", "UsingDecl"
        return DiagnosticAstFieldClass::NamedValue if {"path", "names"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_locations"
        return DiagnosticAstFieldClass::SyntaxScalar if kind == "ImportDecl" && {"exported", "glob"}.includes?(field)
      when "ModuleDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::NamedValue if field == "type_vars"
        return DiagnosticAstFieldClass::SyntaxScalar if {"splat_index", "doc", "visibility", "iyi_unit"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "AnnotationDef"
        return DiagnosticAstFieldClass::Child if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "TypeDeclaration"
        return DiagnosticAstFieldClass::Child if {"var", "declared_type", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
        return DiagnosticAstFieldClass::Infrastructure if field == "discarded"
      when "UninitializedVar"
        return DiagnosticAstFieldClass::Child if {"var", "declared_type"}.includes?(field)
      when "ProcLiteral"
        return DiagnosticAstFieldClass::Child if field == "def"
        return DiagnosticAstFieldClass::Infrastructure if {"proc_pointer", "force_nil", "expected_return_type", "from_block"}.includes?(field)
      when "ProcPointer"
        return DiagnosticAstFieldClass::Child if field == "obj"
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "global"
        return DiagnosticAstFieldClass::Infrastructure if {"call", "expanded"}.includes?(field)
      when "Include", "Extend", "Metaclass"
        return DiagnosticAstFieldClass::Child if field == "name"
      when "LibDef"
        return DiagnosticAstFieldClass::Child if {"name", "body"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "FunDef"
        return DiagnosticAstFieldClass::NamedValue if {"name", "real_name"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "args"
        return DiagnosticAstFieldClass::Child if {"return_type", "body"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "varargs"}.includes?(field)
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
        return DiagnosticAstFieldClass::Infrastructure if field == "external"
      when "TypeDef"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "type_spec"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
        return DiagnosticAstFieldClass::OriginEvidence if field == "name_location"
      when "CStructOrUnionDef"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::Child if field == "body"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "union"}.includes?(field)
      when "EnumDef"
        return DiagnosticAstFieldClass::Child if {"name", "base_type"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if field == "members"
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
        return DiagnosticAstFieldClass::Infrastructure if field == "resolved_type"
      when "ExternalVar"
        return DiagnosticAstFieldClass::NamedValue if {"name", "real_name"}.includes?(field)
        return DiagnosticAstFieldClass::Child if field == "type_spec"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "doc"
      when "Alias"
        return DiagnosticAstFieldClass::Child if {"name", "value"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "visibility", "exported"}.includes?(field)
      when "Cast", "NilableCast"
        return DiagnosticAstFieldClass::Child if {"obj", "to"}.includes?(field)
      when "Annotation"
        return DiagnosticAstFieldClass::Child if field == "path"
        return DiagnosticAstFieldClass::ChildList if {"args", "named_args"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if {"doc", "iyi_file_mark"}.includes?(field)
      when "MacroExpression"
        return DiagnosticAstFieldClass::Child if field == "exp"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "output"
      when "MacroIf"
        return DiagnosticAstFieldClass::Child if {"cond", "then", "else"}.includes?(field)
        return DiagnosticAstFieldClass::SyntaxScalar if field == "is_unless"
      when "MacroFor"
        return DiagnosticAstFieldClass::ChildList if field == "vars"
        return DiagnosticAstFieldClass::Child if {"exp", "body"}.includes?(field)
      when "MacroVar"
        return DiagnosticAstFieldClass::NamedValue if field == "name"
        return DiagnosticAstFieldClass::ChildList if field == "exps"
      when "MagicConstant"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "name"
      when "Asm"
        return DiagnosticAstFieldClass::SyntaxScalar if {"text", "clobbers", "volatile", "alignstack", "intel", "can_throw"}.includes?(field)
        return DiagnosticAstFieldClass::ChildList if {"outputs", "inputs"}.includes?(field)
      when "AsmOperand"
        return DiagnosticAstFieldClass::SyntaxScalar if field == "constraint"
        return DiagnosticAstFieldClass::Child if field == "exp"
      end
      raise ArgumentError.new("unclassified AST field #{kind}.#{field}")
    end

    # Call with a statically narrowed concrete node. The generic ASTNode type
    # cannot establish coverage of the subclass's stored fields.
    def self.validate_reflected_fields(node : T) : Nil forall T
      {% if T == ASTNode %}
        raise ArgumentError.new("AST field coverage requires a concrete node type")
      {% else %}
        kind = node.class.name.rpartition("::")[2]
        {% for ivar in T.instance_vars %}
          classify(kind, {{ivar.name.stringify}})
        {% end %}
      {% end %}
    end

    def self.validate_node_fields(node : ASTNode) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified AST node #{class_name}")
      end
      {% if Iyi::Block.has_method?(:binder) %}
        DiagnosticSemanticDefaults.verify!(node)
      {% end %}
      {% begin %}
        case node
        {% for name in SUPPORTED %}
        when {{name.id}}
          validate_reflected_fields(node.as({{name.id}}))
        {% end %}
        else
          raise ArgumentError.new("unclassified AST node #{class_name}")
        end
      {% end %}
    end

    # Compile-time census of concrete `ASTNode` descendants, enumerated from the
    # type hierarchy and never from SUPPORTED. Abstract bases are skipped. Each
    # concrete node contributes its stored instance variables, so a new node or
    # field appears in this census without anyone naming it here.
    macro concrete_census_kinds
      [
        {% for sub in Iyi::ASTNode.all_subclasses %}
          {% unless sub.abstract? %}
            {{ sub.name.split("::").last }},
          {% end %}
        {% end %}
      ] of String
    end

    macro concrete_census_pairs
      [
        {% for sub in Iyi::ASTNode.all_subclasses %}
          {% unless sub.abstract? %}
            {% for ivar in sub.instance_vars %}
              { {{ sub.name.split("::").last }}, {{ ivar.name.stringify }}.lchop("@") },
            {% end %}
          {% end %}
        {% end %}
      ] of {String, String}
    end

    def self.census_kinds : Array(String)
      concrete_census_kinds
    end

    def self.census_pairs : Array({String, String})
      concrete_census_pairs
    end
  end

  # Direct syntax edges for the types below. The caller must separately encode
  # field presence, scalars, name evidence and origin metadata. This helper is
  # not a complete census and must not be used to authorize a capture.
  module DiagnosticDirectChildFields
    def self.each(node : ASTNode, & : String, Int32?, String?, ASTNode ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified direct AST node #{class_name}")
      end
      case node
      when Path
        # Path.names are scalar names, not child AST nodes.
      when Generic
        yield "name", nil, nil, node.name
        node.type_vars.each_with_index { |child, index| yield "type_vars", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
      when Union
        node.types.each_with_index { |child, index| yield "types", index, nil, child }
      when TypeOf
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when ProcNotation
        node.inputs.try &.each_with_index { |child, index| yield "inputs", index, nil, child }
        node.output.try { |child| yield "output", nil, nil, child }
      when NamedArgument
        yield "value", nil, nil, node.value
      when Arg
        node.default_value.try { |child| yield "default_value", nil, nil, child }
        node.restriction.try { |child| yield "restriction", nil, nil, child }
        node.parsed_annotations.try &.each_with_index { |child, index| yield "parsed_annotations", index, nil, child }
      when Def
        node.receiver.try { |child| yield "receiver", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.double_splat.try { |child| yield "double_splat", nil, nil, child }
        yield "body", nil, nil, node.body
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
        node.return_type.try { |child| yield "return_type", nil, nil, child }
        node.free_var_bounds.try &.each { |key, child| yield "free_var_bounds", nil, key, child }
        node.where_bounds.try &.each { |key, child| yield "where_bounds", nil, key, child }
      when Annotation
        yield "path", nil, nil, node.path
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
      when Nop, NilLiteral, ImplicitObj, Self, Underscore, BoolLiteral, NumberLiteral, CharLiteral,
           StringLiteral, SymbolLiteral, MacroLiteral, Var, InstanceVar, ClassVar, Global, MagicConstant
        # No syntax-child edges.
      when Expressions
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when StringInterpolation
        node.expressions.each_with_index { |child, index| yield "expressions", index, nil, child }
      when ArrayLiteral
        node.elements.each_with_index { |child, index| yield "elements", index, nil, child }
        node.of.try { |child| yield "of", nil, nil, child }
        node.name.try { |child| yield "name", nil, nil, child }
      when TupleLiteral
        node.elements.each_with_index { |child, index| yield "elements", index, nil, child }
      when HashLiteral
        node.entries.each_with_index do |entry, index|
          yield "entries.key", index, nil, entry.key
          yield "entries.value", index, nil, entry.value
        end
        node.of.try do |entry|
          yield "of.key", nil, nil, entry.key
          yield "of.value", nil, nil, entry.value
        end
        node.name.try { |child| yield "name", nil, nil, child }
      when NamedTupleLiteral
        node.entries.each_with_index { |entry, index| yield "entries.value", index, nil, entry.value }
      when RangeLiteral
        yield "from", nil, nil, node.from
        yield "to", nil, nil, node.to
      when RegexLiteral
        yield "value", nil, nil, node.value
      when ReadInstanceVar
        yield "obj", nil, nil, node.obj
      when Block
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        yield "body", nil, nil, node.body
        node.unpacks.try &.each { |index, child| yield "unpacks", index, nil, child }
      when Call
        node.obj.try { |child| yield "obj", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.named_args.try &.each_with_index { |child, index| yield "named_args", index, nil, child }
        node.block.try { |child| yield "block", nil, nil, child }
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
      when If, Unless
        yield "cond", nil, nil, node.cond
        yield "then", nil, nil, node.then
        yield "else", nil, nil, node.else
      when Assign, OpAssign
        yield "target", nil, nil, node.target
        yield "value", nil, nil, node.value
      when MultiAssign
        node.targets.each_with_index { |child, index| yield "targets", index, nil, child }
        node.values.each_with_index { |child, index| yield "values", index, nil, child }
      when And, Or
        yield "left", nil, nil, node.left
        yield "right", nil, nil, node.right
      when Macro
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        yield "body", nil, nil, node.body
        node.double_splat.try { |child| yield "double_splat", nil, nil, child }
        node.block_arg.try { |child| yield "block_arg", nil, nil, child }
      when Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out, MacroVerbatim, Splat, DoubleSplat,
           Propagate, Defer
        yield "exp", nil, nil, node.exp
      when Return, Break, Next
        node.exp.try { |child| yield "exp", nil, nil, child }
      when OffsetOf
        yield "offsetof_type", nil, nil, node.offsetof_type
        yield "offset", nil, nil, node.offset
      when VisibilityModifier
        yield "exp", nil, nil, node.exp
      when IsA
        yield "obj", nil, nil, node.obj
        yield "const", nil, nil, node.const
      when RespondsTo
        yield "obj", nil, nil, node.obj
      when Require
        # Its string is a scalar, not a child AST node.
      when When
        node.conds.each_with_index { |child, index| yield "conds", index, nil, child }
        yield "body", nil, nil, node.body
      when Case
        node.cond.try { |child| yield "cond", nil, nil, child }
        node.whens.each_with_index { |child, index| yield "whens", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
      when Select
        node.whens.each_with_index { |child, index| yield "whens", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
      when While, Until
        yield "cond", nil, nil, node.cond
        yield "body", nil, nil, node.body
      when Rescue
        yield "body", nil, nil, node.body
        node.types.try &.each_with_index { |child, index| yield "types", index, nil, child }
      when ExceptionHandler
        yield "body", nil, nil, node.body
        node.rescues.try &.each_with_index { |child, index| yield "rescues", index, nil, child }
        node.else.try { |child| yield "else", nil, nil, child }
        node.ensure.try { |child| yield "ensure", nil, nil, child }
      when Yield
        node.exps.each_with_index { |child, index| yield "exps", index, nil, child }
        node.scope.try { |child| yield "scope", nil, nil, child }
      when ClassDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
        node.superclass.try { |child| yield "superclass", nil, nil, child }
      when TraitDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
        node.supertraits.try &.each_with_index { |child, index| yield "supertraits", index, nil, child }
      when Recover
        yield "exp", nil, nil, node.exp
        node.default.try { |child| yield "default", nil, nil, child }
      when AssocTypeDecl
        node.value.try { |child| yield "value", nil, nil, child }
      when ImplDef
        yield "trait", nil, nil, node.trait
        yield "target", nil, nil, node.target
        yield "body", nil, nil, node.body
        node.trait_args.try &.each_with_index { |child, index| yield "trait_args", index, nil, child }
        node.type_var_bounds.try &.each { |key, child| yield "type_var_bounds", nil, key, child }
        node.assoc_types.try &.each { |key, child| yield "assoc_types", nil, key, child }
      when ModuleHeader, ImportDecl, UsingDecl
        # Their names and paths are ordered string fields.
      when ModuleDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
      when AnnotationDef
        yield "name", nil, nil, node.name
      when TypeDeclaration
        yield "var", nil, nil, node.var
        yield "declared_type", nil, nil, node.declared_type
        node.value.try { |child| yield "value", nil, nil, child }
      when UninitializedVar
        yield "var", nil, nil, node.var
        yield "declared_type", nil, nil, node.declared_type
      when ProcLiteral
        yield "def", nil, nil, node.def
      when ProcPointer
        node.obj.try { |child| yield "obj", nil, nil, child }
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
      when Include, Extend, Metaclass
        yield "name", nil, nil, node.name
      when LibDef
        yield "name", nil, nil, node.name
        yield "body", nil, nil, node.body
      when FunDef
        node.args.each_with_index { |child, index| yield "args", index, nil, child }
        node.return_type.try { |child| yield "return_type", nil, nil, child }
        node.body.try { |child| yield "body", nil, nil, child }
      when TypeDef
        yield "type_spec", nil, nil, node.type_spec
      when CStructOrUnionDef
        yield "body", nil, nil, node.body
      when EnumDef
        yield "name", nil, nil, node.name
        node.base_type.try { |child| yield "base_type", nil, nil, child }
        node.members.each_with_index { |child, index| yield "members", index, nil, child }
      when ExternalVar
        yield "type_spec", nil, nil, node.type_spec
      when Alias
        yield "name", nil, nil, node.name
        yield "value", nil, nil, node.value
      when Cast, NilableCast
        yield "obj", nil, nil, node.obj
        yield "to", nil, nil, node.to
      when MacroExpression
        yield "exp", nil, nil, node.exp
      when MacroIf
        yield "cond", nil, nil, node.cond
        yield "then", nil, nil, node.then
        yield "else", nil, nil, node.else
      when MacroFor
        node.vars.each_with_index { |child, index| yield "vars", index, nil, child }
        yield "exp", nil, nil, node.exp
        yield "body", nil, nil, node.body
      when MacroVar
        node.exps.try &.each_with_index { |child, index| yield "exps", index, nil, child }
      when Asm
        node.outputs.try &.each_with_index { |child, index| yield "outputs", index, nil, child }
        node.inputs.try &.each_with_index { |child, index| yield "inputs", index, nil, child }
      when AsmOperand
        yield "exp", nil, nil, node.exp
      else
        raise ArgumentError.new("unclassified direct AST child fields for #{node.class}")
      end
    end
  end

  # Name occurrences come from stored syntax fields, never from the selected
  # contributor list. Evidence and field presence must be encoded separately.
  module DiagnosticDirectNameFields
    def self.each(node : ASTNode, & : String, Int32?, String?, String ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified direct AST node #{class_name}")
      end
      case node
      when Path
        node.names.each_with_index { |name, index| yield "names", index, nil, name }
      when Arg
        yield "name", nil, nil, node.name
        yield "external_name", nil, nil, node.external_name
      when SymbolLiteral
        yield "value", nil, nil, node.value
      when NamedArgument, Var, InstanceVar, ClassVar, Global, ReadInstanceVar, Call, Macro, RespondsTo,
           AssocTypeDecl, ProcPointer, TypeDef, CStructOrUnionDef, MacroVar
        yield "name", nil, nil, node.name
      when OpAssign
        yield "op", nil, nil, node.op
      when NamedTupleLiteral
        node.entries.each_with_index { |entry, index| yield "entries.key", index, nil, entry.key }
      when Def
        yield "name", nil, nil, node.name
        node.free_vars.try &.each_with_index { |name, index| yield "free_vars", index, nil, name }
        node.free_var_bounds.try &.each { |key, _| yield "free_var_bounds.key", nil, key, key }
        node.where_bounds.try &.each { |key, _| yield "where_bounds.key", nil, key, key }
      when ClassDef, ModuleDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
      when TraitDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
        node.assoc_types.try &.each_with_index { |name, index| yield "assoc_types", index, nil, name }
      when ImplDef
        node.type_vars.try &.each_with_index { |name, index| yield "type_vars", index, nil, name }
        node.type_var_bounds.try &.each { |key, _| yield "type_var_bounds.key", nil, key, key }
        node.assoc_types.try &.each { |key, _| yield "assoc_types.key", nil, key, key }
      when ModuleHeader
        node.path.each_with_index { |name, index| yield "path", index, nil, name }
      when ImportDecl, UsingDecl
        node.path.each_with_index { |name, index| yield "path", index, nil, name }
        node.names.try &.each_with_index { |name, index| yield "names", index, nil, name }
      when Rescue
        node.name.try { |name| yield "name", nil, nil, name }
      when FunDef
        yield "name", nil, nil, node.name
        yield "real_name", nil, nil, node.real_name
      when ExternalVar
        yield "name", nil, nil, node.name
        node.real_name.try { |name| yield "real_name", nil, nil, name }
      when Nop, NilLiteral, ImplicitObj, Self, Underscore, Expressions, BoolLiteral, NumberLiteral,
           CharLiteral, StringLiteral, MacroLiteral, StringInterpolation, ArrayLiteral,
           HashLiteral, RangeLiteral, RegexLiteral, TupleLiteral, Block, If, Unless, Assign, MultiAssign,
           And, Or, ProcNotation, Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out,
           MacroVerbatim, Splat, DoubleSplat, OffsetOf, VisibilityModifier, IsA, Require, When, Case,
           Select, While, Until, ExceptionHandler, Return, Break, Next, Yield, Propagate, Defer, Recover,
           AnnotationDef, Generic, TypeDeclaration, UninitializedVar, ProcLiteral, Union, Include, Extend,
           LibDef, EnumDef, Alias, Metaclass, Cast, NilableCast, TypeOf, Annotation, MacroExpression,
           MacroIf, MacroFor, MagicConstant, Asm, AsmOperand
        # These nodes have no direct string name fields. Child nodes are
        # enumerated separately by DiagnosticDirectChildFields.
      else
        raise ArgumentError.new("unclassified direct AST name fields for #{class_name}")
      end
    end
  end

  enum DiagnosticFieldPresence
    Absent
    Empty
    Nonempty
    Present
  end

  # Presence reader for the listed field families only. Unsupported kinds
  # fail explicitly rather than acquiring guessed presence semantics.
  module DiagnosticDirectPresenceFields
    private def self.collection(value : Array(T)?) : DiagnosticFieldPresence forall T
      return DiagnosticFieldPresence::Absent unless value
      value.empty? ? DiagnosticFieldPresence::Empty : DiagnosticFieldPresence::Nonempty
    end

    private def self.collection(value : Hash(K, V)?) : DiagnosticFieldPresence forall K, V
      return DiagnosticFieldPresence::Absent unless value
      value.empty? ? DiagnosticFieldPresence::Empty : DiagnosticFieldPresence::Nonempty
    end

    private def self.optional(value) : DiagnosticFieldPresence
      value.nil? ? DiagnosticFieldPresence::Absent : DiagnosticFieldPresence::Present
    end

    def self.each(node : ASTNode, & : String, DiagnosticFieldPresence ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified presence AST node #{class_name}")
      end
      case node
      when Path
        yield "names", collection(node.names)
        {"global", "visibility", "exported"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when Generic
        yield "name", DiagnosticFieldPresence::Present
        yield "type_vars", collection(node.type_vars)
        yield "named_args", collection(node.named_args)
        yield "suffix", DiagnosticFieldPresence::Present
      when Union
        yield "types", collection(node.types)
        yield "parens", DiagnosticFieldPresence::Present
      when TypeOf
        yield "expressions", collection(node.expressions)
      when ProcNotation
        yield "inputs", collection(node.inputs)
        yield "output", optional(node.output)
      when NamedArgument
        yield "name", DiagnosticFieldPresence::Present
        yield "value", DiagnosticFieldPresence::Present
      when Arg
        yield "name", DiagnosticFieldPresence::Present
        yield "external_name", DiagnosticFieldPresence::Present
        yield "default_value", optional(node.default_value)
        yield "restriction", optional(node.restriction)
        yield "parsed_annotations", collection(node.parsed_annotations)
        yield "doc", optional(node.doc)
      when Def
        yield "name", DiagnosticFieldPresence::Present
        yield "free_vars", collection(node.free_vars)
        yield "free_var_bounds", collection(node.free_var_bounds)
        yield "where_bounds", collection(node.where_bounds)
        yield "receiver", optional(node.receiver)
        yield "args", collection(node.args)
        yield "double_splat", optional(node.double_splat)
        yield "body", DiagnosticFieldPresence::Present
        yield "block_arg", optional(node.block_arg)
        yield "return_type", optional(node.return_type)
        yield "block_arity", optional(node.block_arity)
        yield "splat_index", optional(node.splat_index)
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
        {"visibility", "exported", "iyi_from_impl", "macro_def", "abstract", "calls_super",
         "calls_initialize", "calls_previous_def", "uses_block_arg", "assigns_special_var"}.each do |field|
          yield field, DiagnosticFieldPresence::Present
        end
      when Annotation
        yield "path", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "named_args", collection(node.named_args)
        yield "doc", optional(node.doc)
        yield "iyi_file_mark", DiagnosticFieldPresence::Present
      when SymbolLiteral
        yield "value", DiagnosticFieldPresence::Present
      when And, Or
        yield "left", DiagnosticFieldPresence::Present
        yield "right", DiagnosticFieldPresence::Present
      when Expressions
        yield "expressions", collection(node.expressions)
        yield "keyword", DiagnosticFieldPresence::Present
      when BoolLiteral, CharLiteral, StringLiteral, MacroLiteral
        yield "value", DiagnosticFieldPresence::Present
      when NumberLiteral
        yield "value", DiagnosticFieldPresence::Present
        yield "kind", DiagnosticFieldPresence::Present
      when StringInterpolation
        yield "expressions", collection(node.expressions)
        yield "heredoc_indent", DiagnosticFieldPresence::Present
      when ArrayLiteral
        yield "elements", collection(node.elements)
        yield "of", optional(node.of)
        yield "name", optional(node.name)
      when TupleLiteral
        yield "elements", collection(node.elements)
      when HashLiteral
        yield "entries", collection(node.entries)
        yield "of", optional(node.of)
        yield "name", optional(node.name)
      when NamedTupleLiteral
        yield "entries", collection(node.entries)
      when RangeLiteral
        {"from", "to", "exclusive"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when RegexLiteral
        {"value", "options"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when Var
        yield "name", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when InstanceVar, ClassVar, Global
        yield "name", DiagnosticFieldPresence::Present
      when ReadInstanceVar
        yield "obj", DiagnosticFieldPresence::Present
        yield "name", DiagnosticFieldPresence::Present
      when Block
        yield "args", collection(node.args)
        yield "body", DiagnosticFieldPresence::Present
        yield "splat_index", optional(node.splat_index)
        yield "unpacks", collection(node.unpacks)
      when Call
        yield "obj", optional(node.obj)
        yield "name", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "named_args", collection(node.named_args)
        yield "block", optional(node.block)
        yield "block_arg", optional(node.block_arg)
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
        yield "iyi_after_floor_div", optional(node.iyi_after_floor_div)
        {"visibility", "global", "expansion", "args_in_brackets", "has_parentheses", "iyi_group", "iyi_banged"}.each do |field|
          yield field, DiagnosticFieldPresence::Present
        end
      when If, Unless
        {"cond", "then", "else"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "else_location", optional(node.else_location)
        yield "ternary", DiagnosticFieldPresence::Present if node.is_a?(If)
      when Assign
        yield "target", DiagnosticFieldPresence::Present
        yield "value", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when OpAssign
        {"target", "value", "op"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "name_location", optional(node.name_location)
      when MultiAssign
        yield "targets", collection(node.targets)
        yield "values", collection(node.values)
      when Macro
        yield "name", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "body", DiagnosticFieldPresence::Present
        yield "double_splat", optional(node.double_splat)
        yield "block_arg", optional(node.block_arg)
        yield "splat_index", optional(node.splat_index)
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "exported", DiagnosticFieldPresence::Present
      when Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out,
           MacroVerbatim, Splat, DoubleSplat, Propagate, Defer
        yield "exp", DiagnosticFieldPresence::Present
      when Return, Break, Next
        yield "exp", optional(node.exp)
      when OffsetOf
        yield "offsetof_type", DiagnosticFieldPresence::Present
        yield "offset", DiagnosticFieldPresence::Present
      when VisibilityModifier
        yield "exp", DiagnosticFieldPresence::Present
        yield "modifier", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when IsA
        {"obj", "const", "nil_check"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "error_construct", optional(node.error_construct)
        yield "iyi_bang_call", optional(node.iyi_bang_call)
      when RespondsTo
        yield "obj", DiagnosticFieldPresence::Present
        yield "name", DiagnosticFieldPresence::Present
      when Require
        yield "string", DiagnosticFieldPresence::Present
      when When
        yield "conds", collection(node.conds)
        yield "body", DiagnosticFieldPresence::Present
        yield "exhaustive", DiagnosticFieldPresence::Present
      when Case
        yield "cond", optional(node.cond)
        yield "whens", collection(node.whens)
        yield "else", optional(node.else)
        yield "exhaustive", DiagnosticFieldPresence::Present
        yield "binds_it", DiagnosticFieldPresence::Present
      when Select
        yield "whens", collection(node.whens)
        yield "else", optional(node.else)
      when While, Until
        yield "cond", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
      when Rescue
        yield "body", DiagnosticFieldPresence::Present
        yield "types", collection(node.types)
        yield "name", optional(node.name)
      when ExceptionHandler
        yield "body", DiagnosticFieldPresence::Present
        yield "rescues", collection(node.rescues)
        yield "else", optional(node.else)
        yield "ensure", optional(node.ensure)
        yield "implicit", DiagnosticFieldPresence::Present
        yield "suffix", DiagnosticFieldPresence::Present
        yield "else_location", optional(node.else_location)
        yield "ensure_location", optional(node.ensure_location)
      when Yield
        yield "exps", collection(node.exps)
        yield "scope", optional(node.scope)
        yield "has_parentheses", DiagnosticFieldPresence::Present
      when ClassDef
        yield "name", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
        yield "superclass", optional(node.superclass)
        yield "type_vars", collection(node.type_vars)
        yield "name_location", optional(node.name_location)
        yield "doc", optional(node.doc)
        yield "splat_index", optional(node.splat_index)
        {"abstract", "struct", "visibility", "exported"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when TraitDef
        yield "name", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
        yield "type_vars", collection(node.type_vars)
        yield "assoc_types", collection(node.assoc_types)
        yield "supertraits", collection(node.supertraits)
        yield "name_location", optional(node.name_location)
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "exported", DiagnosticFieldPresence::Present
      when Recover
        yield "exp", DiagnosticFieldPresence::Present
        yield "default", optional(node.default)
      when AssocTypeDecl
        yield "name", DiagnosticFieldPresence::Present
        yield "value", optional(node.value)
        yield "in_type_body", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
      when ImplDef
        {"trait", "target", "body"}.each { |field| yield field, DiagnosticFieldPresence::Present }
        yield "trait_args", collection(node.trait_args)
        yield "type_vars", collection(node.type_vars)
        yield "type_var_bounds", collection(node.type_var_bounds)
        yield "assoc_types", collection(node.assoc_types)
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "name_location", optional(node.name_location)
      when ModuleHeader
        yield "path", collection(node.path)
      when ImportDecl, UsingDecl
        yield "path", collection(node.path)
        yield "names", collection(node.names)
        yield "name_locations", collection(node.name_locations)
        if node.is_a?(ImportDecl)
          yield "exported", DiagnosticFieldPresence::Present
          yield "glob", DiagnosticFieldPresence::Present
        end
      when ModuleDef
        yield "name", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
        yield "type_vars", collection(node.type_vars)
        yield "splat_index", optional(node.splat_index)
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "iyi_unit", DiagnosticFieldPresence::Present
        yield "name_location", optional(node.name_location)
      when AnnotationDef
        yield "name", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "exported", DiagnosticFieldPresence::Present
        yield "name_location", optional(node.name_location)
      when TypeDeclaration
        yield "var", DiagnosticFieldPresence::Present
        yield "declared_type", DiagnosticFieldPresence::Present
        yield "value", optional(node.value)
        yield "doc", optional(node.doc)
      when UninitializedVar
        yield "var", DiagnosticFieldPresence::Present
        yield "declared_type", DiagnosticFieldPresence::Present
      when ProcLiteral
        yield "def", DiagnosticFieldPresence::Present
      when ProcPointer
        yield "obj", optional(node.obj)
        yield "name", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "global", DiagnosticFieldPresence::Present
      when Include, Extend, Metaclass
        yield "name", DiagnosticFieldPresence::Present
      when LibDef
        yield "name", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "name_location", optional(node.name_location)
      when FunDef
        yield "name", DiagnosticFieldPresence::Present
        yield "real_name", DiagnosticFieldPresence::Present
        yield "args", collection(node.args)
        yield "return_type", optional(node.return_type)
        yield "body", optional(node.body)
        yield "doc", optional(node.doc)
        yield "varargs", DiagnosticFieldPresence::Present
        yield "name_location", optional(node.name_location)
      when TypeDef
        yield "name", DiagnosticFieldPresence::Present
        yield "type_spec", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "name_location", optional(node.name_location)
      when CStructOrUnionDef
        yield "name", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "union", DiagnosticFieldPresence::Present
      when EnumDef
        yield "name", DiagnosticFieldPresence::Present
        yield "base_type", optional(node.base_type)
        yield "members", collection(node.members)
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "exported", DiagnosticFieldPresence::Present
      when ExternalVar
        yield "name", DiagnosticFieldPresence::Present
        yield "real_name", optional(node.real_name)
        yield "type_spec", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
      when Alias
        yield "name", DiagnosticFieldPresence::Present
        yield "value", DiagnosticFieldPresence::Present
        yield "doc", optional(node.doc)
        yield "visibility", DiagnosticFieldPresence::Present
        yield "exported", DiagnosticFieldPresence::Present
      when Cast, NilableCast
        yield "obj", DiagnosticFieldPresence::Present
        yield "to", DiagnosticFieldPresence::Present
      when MacroExpression
        yield "exp", DiagnosticFieldPresence::Present
        yield "output", DiagnosticFieldPresence::Present
      when MacroIf
        {"cond", "then", "else", "is_unless"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when MacroFor
        yield "vars", collection(node.vars)
        yield "exp", DiagnosticFieldPresence::Present
        yield "body", DiagnosticFieldPresence::Present
      when MacroVar
        yield "name", DiagnosticFieldPresence::Present
        yield "exps", collection(node.exps)
      when MagicConstant
        yield "name", DiagnosticFieldPresence::Present
      when Asm
        yield "text", DiagnosticFieldPresence::Present
        yield "outputs", collection(node.outputs)
        yield "inputs", collection(node.inputs)
        yield "clobbers", collection(node.clobbers)
        {"volatile", "alignstack", "intel", "can_throw"}.each { |field| yield field, DiagnosticFieldPresence::Present }
      when AsmOperand
        yield "constraint", DiagnosticFieldPresence::Present
        yield "exp", DiagnosticFieldPresence::Present
      when Nop, NilLiteral, ImplicitObj, Self, Underscore
        # No syntax-specific stored fields.
      else
        raise ArgumentError.new("unclassified AST presence fields for #{class_name}")
      end
    end
  end

  enum DiagnosticScalarShape
    Null
    Flag
    Number
    Text
    TextList
  end

  # One stored scalar as a single concrete type. The reader yields this rather
  # than a union of Bool, Int32, String and arrays, so every block and nested
  # builder call sees one static type. The shape selects which field is live.
  record DiagnosticScalar, shape : DiagnosticScalarShape, flag : Bool, number : Int32,
    text : String, parts : Array(String)? do
    def self.absent : DiagnosticScalar
      new(DiagnosticScalarShape::Null, false, 0, "", nil)
    end

    def self.flag(value : Bool) : DiagnosticScalar
      new(DiagnosticScalarShape::Flag, value, 0, "", nil)
    end

    def self.number(value : Int32) : DiagnosticScalar
      new(DiagnosticScalarShape::Number, false, value, "", nil)
    end

    def self.text(value : String) : DiagnosticScalar
      new(DiagnosticScalarShape::Text, false, 0, value, nil)
    end

    def self.parts(value : Array(String)) : DiagnosticScalar
      new(DiagnosticScalarShape::TextList, false, 0, "", value)
    end

    def self.optional_number(value : Int32?) : DiagnosticScalar
      value ? number(value) : absent
    end

    def self.optional_text(value : String?) : DiagnosticScalar
      value ? text(value) : absent
    end

    def self.optional_parts(value : Array(String)?) : DiagnosticScalar
      value ? parts(value) : absent
    end

    def self.pair(value : {String, String}?) : DiagnosticScalar
      value ? parts([value[0], value[1]]) : absent
    end
  end

  # Direct scalar reader for the listed kinds. Type tags distinguish enum
  # names, integer optionals, booleans and arbitrary-byte strings.
  module DiagnosticDirectScalarFields
    def self.each(node : ASTNode, & : String, String, DiagnosticScalar ->) : Nil
      class_name = node.class.name
      kind = class_name.rpartition("::")[2]
      unless class_name == "Iyi::#{kind}" && DiagnosticAstFieldSchema::SUPPORTED.includes?(kind)
        raise ArgumentError.new("unclassified scalar AST node #{class_name}")
      end
      case node
      when Path
        yield "global", "bool", DiagnosticScalar.flag(node.global?)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when Generic
        yield "suffix", "Generic::Suffix", DiagnosticScalar.text(node.suffix.to_s)
      when Union
        yield "parens", "bool", DiagnosticScalar.flag(node.parens?)
      when Arg
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when Def
        yield "block_arity", "int32?", DiagnosticScalar.optional_number(node.block_arity)
        yield "splat_index", "int32?", DiagnosticScalar.optional_number(node.splat_index)
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
        yield "iyi_from_impl", "bool", DiagnosticScalar.flag(node.iyi_from_impl?)
        yield "macro_def", "bool", DiagnosticScalar.flag(node.macro_def?)
        yield "abstract", "bool", DiagnosticScalar.flag(node.abstract?)
        yield "calls_super", "bool", DiagnosticScalar.flag(node.calls_super?)
        yield "calls_initialize", "bool", DiagnosticScalar.flag(node.calls_initialize?)
        yield "calls_previous_def", "bool", DiagnosticScalar.flag(node.calls_previous_def?)
        yield "uses_block_arg", "bool", DiagnosticScalar.flag(node.uses_block_arg?)
        yield "assigns_special_var", "bool", DiagnosticScalar.flag(node.assigns_special_var?)
      when Annotation
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "iyi_file_mark", "bool", DiagnosticScalar.flag(node.iyi_file_mark?)
      when Expressions
        yield "keyword", "Expressions::Keyword", DiagnosticScalar.text(node.keyword.to_s)
      when BoolLiteral
        yield "value", "bool", DiagnosticScalar.flag(node.value)
      when NumberLiteral
        yield "value", "bytes", DiagnosticScalar.text(node.value)
        yield "kind", "NumberKind", DiagnosticScalar.text(node.kind.to_s)
      when CharLiteral
        yield "value", "char", DiagnosticScalar.number(node.value.ord)
      when StringLiteral, MacroLiteral
        yield "value", "bytes", DiagnosticScalar.text(node.value)
      when StringInterpolation
        yield "heredoc_indent", "int32", DiagnosticScalar.number(node.heredoc_indent)
      when RangeLiteral
        yield "exclusive", "bool", DiagnosticScalar.flag(node.exclusive?)
      when RegexLiteral
        yield "options", "RegexOptions", DiagnosticScalar.number(node.options.value.to_i32)
      when Var
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when Block
        yield "splat_index", "int32?", DiagnosticScalar.optional_number(node.splat_index)
      when Call
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "global", "bool", DiagnosticScalar.flag(node.global?)
        yield "expansion", "bool", DiagnosticScalar.flag(node.expansion?)
        yield "args_in_brackets", "bool", DiagnosticScalar.flag(node.args_in_brackets?)
        yield "has_parentheses", "bool", DiagnosticScalar.flag(node.has_parentheses?)
        yield "iyi_group", "bool", DiagnosticScalar.flag(node.iyi_group?)
        yield "iyi_banged", "bool", DiagnosticScalar.flag(node.iyi_banged?)
      when If
        yield "ternary", "bool", DiagnosticScalar.flag(node.ternary?)
      when Assign
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when Macro
        yield "splat_index", "int32?", DiagnosticScalar.optional_number(node.splat_index)
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when VisibilityModifier
        yield "modifier", "Visibility", DiagnosticScalar.text(node.modifier.to_s)
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when IsA
        yield "nil_check", "bool", DiagnosticScalar.flag(node.nil_check?)
        yield "error_construct", "bytes?", DiagnosticScalar.optional_text(node.error_construct)
        yield "iyi_bang_call", "bytes_pair?", DiagnosticScalar.pair(node.iyi_bang_call)
      when Require
        yield "string", "bytes", DiagnosticScalar.text(node.string)
      when When
        yield "exhaustive", "bool", DiagnosticScalar.flag(node.exhaustive?)
      when Case
        yield "exhaustive", "bool", DiagnosticScalar.flag(node.exhaustive?)
        yield "binds_it", "bool", DiagnosticScalar.flag(node.binds_it?)
      when ExceptionHandler
        yield "implicit", "bool", DiagnosticScalar.flag(node.implicit)
        yield "suffix", "bool", DiagnosticScalar.flag(node.suffix)
      when Yield
        yield "has_parentheses", "bool", DiagnosticScalar.flag(node.has_parentheses?)
      when Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf, Out,
           MacroVerbatim, Splat, DoubleSplat, Propagate, Defer, Return, Break, Next,
           OffsetOf, RespondsTo, Select, While, Until, Rescue
        # Their syntax-specific fields are names, children, or collections.
      when ClassDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "splat_index", "int32?", DiagnosticScalar.optional_number(node.splat_index)
        yield "abstract", "bool", DiagnosticScalar.flag(node.abstract?)
        yield "struct", "bool", DiagnosticScalar.flag(node.struct?)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when TraitDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when AssocTypeDecl
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "in_type_body", "bool", DiagnosticScalar.flag(node.in_type_body?)
      when ImplDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
      when ImportDecl
        yield "exported", "bool", DiagnosticScalar.flag(node.exported)
        yield "glob", "bool", DiagnosticScalar.flag(node.glob?)
      when ModuleDef
        yield "splat_index", "int32?", DiagnosticScalar.optional_number(node.splat_index)
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "iyi_unit", "bool", DiagnosticScalar.flag(node.iyi_unit?)
      when AnnotationDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when TypeDeclaration
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when ProcPointer
        yield "global", "bool", DiagnosticScalar.flag(node.global?)
      when LibDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
      when FunDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "varargs", "bool", DiagnosticScalar.flag(node.varargs?)
      when TypeDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when CStructOrUnionDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "union", "bool", DiagnosticScalar.flag(node.union?)
      when EnumDef
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when ExternalVar
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
      when Alias
        yield "doc", "bytes?", DiagnosticScalar.optional_text(node.doc)
        yield "visibility", "Visibility", DiagnosticScalar.text(node.visibility.to_s)
        yield "exported", "bool", DiagnosticScalar.flag(node.exported?)
      when MacroExpression
        yield "output", "bool", DiagnosticScalar.flag(node.output?)
      when MacroIf
        yield "is_unless", "bool", DiagnosticScalar.flag(node.is_unless?)
      when MagicConstant
        yield "name", "Token::Kind", DiagnosticScalar.text(node.name.to_s)
      when Asm
        yield "text", "bytes", DiagnosticScalar.text(node.text)
        yield "clobbers", "bytes_array?", DiagnosticScalar.optional_parts(node.clobbers)
        yield "volatile", "bool", DiagnosticScalar.flag(node.volatile?)
        yield "alignstack", "bool", DiagnosticScalar.flag(node.alignstack?)
        yield "intel", "bool", DiagnosticScalar.flag(node.intel?)
        yield "can_throw", "bool", DiagnosticScalar.flag(node.can_throw?)
      when AsmOperand
        yield "constraint", "bytes", DiagnosticScalar.text(node.constraint)
      when Recover, ModuleHeader, UsingDecl, UninitializedVar, ProcLiteral, Include, Extend, Metaclass,
           Cast, NilableCast, MacroFor, MacroVar
        # Their syntax-specific fields are names, children, or collections.
      when ArrayLiteral, TupleLiteral, HashLiteral, NamedTupleLiteral, InstanceVar, ClassVar, Global,
           ReadInstanceVar, Unless, OpAssign, MultiAssign
        # Their syntax-specific fields are names, children, or collections.
      when TypeOf, ProcNotation, NamedArgument, SymbolLiteral, And, Or, Nop, NilLiteral, ImplicitObj, Self, Underscore
        # Their syntax-specific fields are names, children, or collections.
      else
        raise ArgumentError.new("unclassified AST scalar fields for #{class_name}")
      end
    end
  end

  record DiagnosticInventoryStep, field : String, index : Int32?, map_key : String? do
    def initialize(@field : String, @index : Int32?, @map_key : String?)
      raise ArgumentError.new("empty inventory field") if @field.empty?
      raise ArgumentError.new("negative inventory index") if @index.try { |index| index < 0 }
      raise ArgumentError.new("ambiguous inventory coordinate") if @index && @map_key
    end
  end

  # One AST node object, written by the snapshot and by the frame walker alike.
  # Subclasses decide how a filename and a child node are written. Each
  # instance holds its own evidence budget, so every writer charges its own bound.
  abstract class DiagnosticAstNodeBody
    MAX_BYTES = 8_i64 * 1024 * 1024
    MAX_DEPTH = 128
    @evidence_budget : UInt64

    def initialize(@evidence_budget : UInt64)
    end

    abstract def write_filename_field(json : JSON::Builder, filename : String | VirtualFile | Nil) : Nil
    abstract def write_child_node(json : JSON::Builder, child : ASTNode, depth : Int32) : Nil

    protected def write_node_object(json : JSON::Builder, node : ASTNode, depth : Int32, owner_id : Int32) : Nil
      charge_evidence(64_u64, 0, depth)
      DiagnosticAstFieldSchema.validate_node_fields(node)
      if !node.is_a?(Arg) && node.diagnostic_external_explicit
        raise ArgumentError.new("external-name observation on non-argument node")
      end
      json.object do
        json.field "owner_id", owner_id
        json.field "kind", node.class.name
        json.field("presence") { write_presence(json, node) }
        json.field("scalars") { write_scalars(json, node) }
        json.field("location") { write_stored_location(json, node.diagnostic_stored_location) }
        json.field("end_location") { write_stored_location(json, node.diagnostic_stored_end_location) }
        json.field("extra_locations") { write_extra_locations(json, node) }
        if origin = node.diagnostic_origin
          charge_evidence(origin.graph_bytes, origin.graph_depth, depth)
        end
        json.field "origin", node.diagnostic_origin
        json.field "macro_lineage", node.diagnostic_macro_lineage.to_s
        json.field "external_name_explicit", node.diagnostic_external_explicit
        json.field("name_slots") { write_name_slots(json, node, depth) }
        json.field("literal_names") { write_literal_names(json, node, depth) }
        json.field("literal_productions") { write_literal_productions(json, node) }
        json.field "names" do
          json.array do
            DiagnosticDirectNameFields.each(node) do |field, index, key, value|
              raise ArgumentError.new("AST inventory name exceeds size limit") if value.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
              json.object do
                json.field "field", field
                json.field "index", index
                json.field "map_key_base64", encode_key(key)
                json.field "value_base64", Base64.strict_encode(value.to_slice)
              end
            end
          end
        end
        json.field "children" do
          json.array do
            DiagnosticDirectChildFields.each(node) do |field, index, key, child|
              json.object do
                json.field "field", field
                json.field "index", index
                json.field "map_key_base64", encode_key(key)
                json.field("node") { write_child_node(json, child, depth + 1) }
              end
            end
          end
        end
      end
    end

    private def write_presence(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        DiagnosticDirectPresenceFields.each(node) do |field, state|
          json.object do
            json.field "field", field
            json.field "state", state.to_s
          end
        end
      end
    end

    private def write_scalars(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        DiagnosticDirectScalarFields.each(node) do |field, type, value|
          json.object do
            json.field "field", field
            json.field "type", type
            json.field("value") { write_scalar_value(json, value) }
          end
        end
      end
    end

    private def write_scalar_value(json : JSON::Builder, value : DiagnosticScalar) : Nil
      case value.shape
      when DiagnosticScalarShape::Null
        json.null
      when DiagnosticScalarShape::Flag
        json.bool(value.flag)
      when DiagnosticScalarShape::Number
        json.number(value.number)
      when DiagnosticScalarShape::Text
        write_scalar_string(json, value.text)
      when DiagnosticScalarShape::TextList
        json.array { value.parts.not_nil!.each { |part| write_scalar_string(json, part) } }
      end
    end

    private def write_scalar_string(json : JSON::Builder, value : String) : Nil
      raise ArgumentError.new("AST scalar exceeds size limit") if value.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
      json.string(Base64.strict_encode(value.to_slice))
    end

    private def write_extra_locations(json : JSON::Builder, node : ASTNode) : Nil
      json.array do
        case node
        when Def, Macro, ClassDef, TraitDef, AssocTypeDecl, ImplDef, ModuleDef, AnnotationDef, LibDef, FunDef, TypeDef
          write_named_location(json, "name_location", node.name_location)
        when Call
          write_named_location(json, "name_location", node.name_location)
          write_named_location(json, "iyi_after_floor_div", node.iyi_after_floor_div)
        when If, Unless
          write_named_location(json, "else_location", node.else_location)
        when OpAssign
          write_named_location(json, "name_location", node.name_location)
        when ExceptionHandler
          write_named_location(json, "else_location", node.else_location)
          write_named_location(json, "ensure_location", node.ensure_location)
        when ImportDecl, UsingDecl
          json.object do
            json.field "field", "name_locations"
            json.field "value" do
              if locations = node.name_locations
                json.array { locations.each { |location| write_stored_location(json, location) } }
              else
                json.null
              end
            end
          end
        when Path, Generic, Union, TypeOf, ProcNotation, NamedArgument, Arg, Annotation,
             SymbolLiteral, And, Or, Nop, NilLiteral, ImplicitObj, Self, Underscore,
             Expressions, BoolLiteral, CharLiteral, StringLiteral, MacroLiteral, NumberLiteral,
             StringInterpolation, ArrayLiteral, TupleLiteral, HashLiteral, NamedTupleLiteral,
             RangeLiteral, RegexLiteral, Var, InstanceVar, ClassVar, Global, ReadInstanceVar,
             Block, Assign, MultiAssign, Not, PointerOf, SizeOf, InstanceSizeOf, AlignOf, InstanceAlignOf,
             Out, MacroVerbatim, Splat, DoubleSplat, Propagate, Defer, Return, Break, Next, OffsetOf,
             VisibilityModifier, IsA, RespondsTo, Require, When, Case, Select, While, Until, Rescue, Yield,
             Recover, ModuleHeader, TypeDeclaration, UninitializedVar, ProcLiteral, ProcPointer, Include, Extend,
             CStructOrUnionDef, EnumDef, ExternalVar, Alias, Metaclass, Cast, NilableCast, MacroExpression,
             MacroIf, MacroFor, MacroVar, MagicConstant, Asm, AsmOperand
          # These kinds have no additional location field in their syntax schema.
        else
          raise ArgumentError.new("unclassified AST extra location fields for #{node.class}")
        end
      end
    end

    private def write_named_location(json : JSON::Builder, field : String, location : Location?) : Nil
      json.object do
        json.field "field", field
        json.field("value") { write_stored_location(json, location) }
      end
    end

    private def write_stored_location(json : JSON::Builder, location : Location?) : Nil
      unless location
        json.null
        return
      end
      json.object do
        write_filename_field(json, location.filename)
        json.field "line", location.line_number
        json.field "column", location.column_number
        json.field "artifact", location.artifact
      end
    end

    private def charge_evidence(bytes : UInt64, graph_depth : Int32, depth : Int32) : Nil
      if graph_depth.to_i64 + depth > MAX_DEPTH || bytes > @evidence_budget
        raise ArgumentError.new("AST inventory evidence exceeds graph limit")
      end
      @evidence_budget -= bytes
    end

    private def write_name_slots(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      count = node.diagnostic_name_slots_count
      unless count
        json.null
        return
      end
      if node.diagnostic_name_slots_graph_bytes > @evidence_budget
        raise ArgumentError.new("AST inventory name evidence exceeds graph limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, depth)
      slots = [] of {DiagnosticNameSlot, Array(DiagnosticNameValue)}
      node.each_diagnostic_name_slot do |slot, values|
        charge_evidence(values.size.to_u64 * 32_u64, 0, depth)
        slots << {slot, values.to_a}
      end
      json.array do
        slots.sort_by { |entry| {entry[0].kind.value, entry[0].index} }.each do |slot, values|
          json.object do
            json.field "kind", slot.kind.to_s
            json.field "index", slot.index
            json.field "values" do
              json.array do
                values.each do |value|
                  case value
                  when DiagnosticNameValue::Observed
                    token = value.source_token
                    graph_depth = token.lexical_origin.graph_depth
                    if binding = token.binding_origin
                      graph_depth = Math.max(graph_depth, binding.graph_depth)
                    end
                    charge_evidence(value.graph_bytes, graph_depth, depth)
                  when DiagnosticNameValue::Derived
                    charge_evidence(value.graph_bytes, value.origin.graph_depth, depth)
                  else
                    raise ArgumentError.new("unclassified AST name evidence")
                  end
                  value.to_json(json)
                end
              end
            end
          end
        end
      end
    end

    private def write_literal_names(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      count = node.diagnostic_literal_names_count
      unless count
        json.null
        return
      end
      if node.diagnostic_literal_names_encoded_bytes > MAX_BYTES.to_u64
        raise ArgumentError.new("AST inventory literal evidence exceeds size limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, depth)
      names = [] of Tuple(Tuple(String, Int32), DiagnosticParsedLiteral)
      node.each_diagnostic_literal_name { |key, literal| names << {key, literal} }
      json.array do
        names.sort_by { |entry| entry[0] }.each do |key, literal|
          json.object do
            json.field "field", key[0]
            json.field "index", key[1]
            json.field "input_sha256", literal.input_sha256
            json.field "input_bytesize", literal.input_bytesize
            json.field "lexical_mode", literal.lexical_mode
            json.field "decoded_base64", literal.decoded_base64
            json.field "segments" do
              json.array do
                charge_evidence(literal.segments_count.to_u64 * 32_u64, 0, depth)
                literal.each_segment do |segment|
                  json.object do
                    json.field "start", segment.start_offset
                    json.field "end", segment.end_offset
                    json.field "raw_base64", segment.raw_base64
                  end
                end
              end
            end
            json.field "expansion" do
              if expansion = literal.expansion
                charge_evidence(expansion[0].graph_bytes, expansion[0].graph_depth, depth)
                charge_evidence(expansion[1].graph_bytes, expansion[1].graph_depth, depth)
                json.object do
                  json.field "invocation", expansion[0]
                  json.field "definition", expansion[1]
                  json.field "guard", expansion[2]
                end
              else
                json.null
              end
            end
          end
        end
      end
    end

    private def write_literal_productions(json : JSON::Builder, node : ASTNode) : Nil
      count = node.diagnostic_literal_productions_count
      unless count
        json.null
        return
      end
      if node.diagnostic_literal_productions_raw_bytes > MAX_BYTES.to_u64
        raise ArgumentError.new("AST inventory literal production exceeds size limit")
      end
      charge_evidence(count.to_u64 * 64_u64, 0, 0)
      productions = [] of Tuple(Tuple(String, Int32), Array(DiagnosticLiteralProductionSegment))
      node.each_diagnostic_literal_production do |key, segments|
        charge_evidence(segments.size.to_u64 * 32_u64, 0, 0)
        productions << {key, segments.to_a}
      end
      json.array do
        productions.sort_by { |entry| entry[0] }.each do |key, segments|
          json.object do
            json.field "field", key[0]
            json.field "index", key[1]
            json.field "segments" do
              json.array do
                segments.each do |segment|
                  json.object do
                    json.field "production", segment.production.to_s
                    json.field "start", segment.start_offset
                    json.field "end", segment.end_offset
                    json.field "raw_base64", segment.raw_base64
                    json.field "delimiter_kind", segment.delimiter_kind
                    json.field "nest", segment.nest
                    json.field "end_delimiter", segment.end_delimiter
                    json.field "allow_escapes", segment.allow_escapes
                    json.field "witnesses" do
                      json.array do
                        charge_evidence(segment.witnesses_count.to_u64 * 32_u64, 0, 0)
                        segment.each_witness do |witness|
                          json.object do
                            json.field "kind", witness.kind.to_s
                            json.field "start", witness.start_offset
                            json.field "end", witness.end_offset
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    private def encode_key(key : String?) : String?
      return nil unless key
      raise ArgumentError.new("AST inventory key exceeds size limit") if key.bytesize.to_i64 > MAX_BYTES * 3 // 4 - 4
      Base64.strict_encode(key.to_slice)
    end
  end

  # Bounded partial syntax inventory. Unsupported presence or scalar readers
  # refuse capture. It is not a registry: parser acceptance, complete field
  # coverage, source-witness binding and authority still need validation.
  class DiagnosticAstInventorySnapshot < DiagnosticAstNodeBody
    MAX_BYTES = DiagnosticAstNodeBody::MAX_BYTES
    MAX_DEPTH = DiagnosticAstNodeBody::MAX_DEPTH
    @sha256 : String
    @bytes : String
    @active = Set(UInt64).new
    @object_ids = {} of UInt64 => Int32

    def initialize(root : ASTNode)
      super(DiagnosticOrigin::MAX_UNFOLDED_BYTES)
      output = DiagnosticCaptureOutput.new(MAX_BYTES)
      json = JSON::Builder.new(output)
      json.max_nesting = 1024
      json.start_document
      write_node(json, root, 0)
      json.end_document
      @bytes = output.snapshot
      @sha256 = ::Crystal::Digest::SHA256.hexdigest(@bytes)
    end

    def bytes : String
      String.new(@bytes.to_slice)
    end

    def sha256 : String
      String.new(@sha256.to_slice)
    end

    # Resolves only the inventory's own name bytes. It cannot establish source
    # provenance or authorize a transformed artifact.
    def resolve_name(owner_path : Array(DiagnosticInventoryStep), field : DiagnosticInventoryStep) : Bytes
      raise ArgumentError.new("inventory path exceeds depth limit") if owner_path.size > MAX_DEPTH
      parser = JSON::Parser.new(@bytes)
      parser.max_nesting = 1024
      node = parser.parse
      owner_path.each do |step|
        node = find_coordinate(node["children"].as_a, step)["node"]
      end
      encoded = find_coordinate(node["names"].as_a, field)["value_base64"].as_s
      Base64.decode(encoded)
    end

    private def find_coordinate(entries : Array(JSON::Any), step : DiagnosticInventoryStep) : JSON::Any
      encoded_key = encode_key(step.map_key)
      found : JSON::Any? = nil
      entries.each do |entry|
        next unless entry["field"].as_s == step.field
        next unless entry["index"].as_i? == step.index
        next unless entry["map_key_base64"].as_s? == encoded_key
        raise ArgumentError.new("ambiguous inventory coordinate") if found
        found = entry
      end
      found || raise ArgumentError.new("unknown inventory coordinate")
    end

    private def write_node(json : JSON::Builder, node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("AST inventory exceeds depth limit") if depth > MAX_DEPTH
      id = node.object_id
      raise ArgumentError.new("cyclic AST inventory") unless @active.add?(id)
      begin
        owner_id = @object_ids[id]?
        unless owner_id
          owner_id = @object_ids.size
          @object_ids[id] = owner_id
        end
        write_node_object(json, node, depth, owner_id)
      ensure
        @active.delete(id)
      end
    end

    def write_filename_field(json : JSON::Builder, filename : String | VirtualFile | Nil) : Nil
      snapshot = DiagnosticFilenameSnapshot.new(filename)
      json.field "filename_snapshot", snapshot.bytes
    end

    def write_child_node(json : JSON::Builder, child : ASTNode, depth : Int32) : Nil
      write_node(json, child, depth)
    end

  end

  # One parser-observed literal constituent, represented as bytes rather than
  # as a UTF-8 string. Offsets are into the exact parser input.
  record DiagnosticLiteralSegment, start_offset : Int32, end_offset : Int32, raw_base64 : String

  # These observations describe what the parser actually consumed. They are
  # not authoritative until bound to an input and validated by the census.
  enum DiagnosticLiteralProduction
    Delimiter
    StringPiece
    SymbolToken
    PercentSymbolElement
    CharToken
    MagicFile
    MagicDir
    PercentStringElement
    Heredoc
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
      if @production.delimiter? || @production.percent_symbol_element? || @production.string_piece? ||
         @production.percent_string_element? || @production.heredoc?
        if @delimiter_kind.nil? || @nest.nil? || @end_delimiter.nil? || @allow_escapes.nil?
          raise ArgumentError.new("delimiter production lacks delimiter state")
        end
        valid_kind = case @production
                     when .delimiter?              then {"STRING", "REGEX", "COMMAND"}.includes?(@delimiter_kind)
                     when .string_piece?           then {"STRING", "REGEX", "COMMAND", "STRING_ARRAY"}.includes?(@delimiter_kind)
                     when .percent_symbol_element? then @delimiter_kind == "SYMBOL_ARRAY"
                     when .percent_string_element? then @delimiter_kind == "STRING_ARRAY"
                     when .heredoc?                then @delimiter_kind == "HEREDOC" && @nest.try(&.empty?) == false && @nest == @end_delimiter
                     else                               false
                     end
        raise ArgumentError.new("invalid literal delimiter production") unless valid_kind
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

    def witnesses_count : Int32
      @witnesses.size
    end

    def each_witness(& : DiagnosticLiteralWitness ->) : Nil
      @witnesses.each { |witness| yield witness }
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

    def segments_count : Int32
      @segments.size
    end

    def each_segment(& : DiagnosticLiteralSegment ->) : Nil
      @segments.each { |segment| yield segment }
    end

    # Validates canonical RFC 4648 base64 without allocating decoded bytes.
    def decoded_bytesize : Int32
      encoded = @decoded_base64
      size = encoded.bytesize
      raise ArgumentError.new("literal decoded value exceeds size limit") if size.to_u64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES
      raise ArgumentError.new("invalid literal base64 length") unless size % 4 == 0
      return 0 if size == 0
      padding = encoded.byte_at(size - 1) == 61_u8 ? 1 : 0
      padding += 1 if padding == 1 && encoded.byte_at(size - 2) == 61_u8
      (0...(size - padding)).each do |index|
        raise ArgumentError.new("invalid literal base64 alphabet") unless base64_value(encoded.byte_at(index))
      end
      if padding > 0
        value = base64_value(encoded.byte_at(size - padding - 1))
        raise ArgumentError.new("invalid literal base64 padding") unless value
        mask = padding == 2 ? 15 : 3
        raise ArgumentError.new("noncanonical literal base64 padding") unless (value & mask) == 0
      end
      (size // 4) * 3 - padding
    end

    private def base64_value(byte : UInt8) : Int32?
      case byte
      when 65_u8..90_u8  then byte.to_i - 65
      when 97_u8..122_u8 then byte.to_i - 97 + 26
      when 48_u8..57_u8  then byte.to_i - 48 + 52
      when 43_u8         then 62
      when 47_u8         then 63
      else                    nil
      end
    end
  end

  # Checks byte binding only. Production semantics, owner coordinates and
  # expansion ancestry still require the complete registry validator.
  module DiagnosticLiteralInputChecks
    # Associates a quoted-name observation with the actual stored field. This
    # does not establish an original owner path or authorize registry use.
    def self.verify_owner_field!(node : ASTNode, field : String, index : Int32,
                                 input : AcceptedCaptureInput) : Nil
      expected = owner_value(node, field, index)
      max_count = DiagnosticOrigin::MAX_UNFOLDED_BYTES // 64
      if (node.diagnostic_literal_names_count || 0).to_u64 > max_count ||
         (node.diagnostic_literal_productions_count || 0).to_u64 > max_count
        raise ArgumentError.new("literal owner evidence count exceeds size limit")
      end
      literal : DiagnosticParsedLiteral? = nil
      production : Indexable(DiagnosticLiteralProductionSegment)? = nil
      node.each_diagnostic_literal_name do |key, value|
        literal = value if key == {field, index}
      end
      node.each_diagnostic_literal_production do |key, value|
        production = value if key == {field, index}
      end
      literal ||= raise ArgumentError.new("literal owner observation missing")
      production ||= raise ArgumentError.new("literal owner production missing")
      verify_input_bytes!(literal, production, expected, input)
    end

    # The caller must obtain both supplied values from this owner's matching
    # metadata entries; this method itself does not prove that association.
    def self.verify_owner_observation!(node : ASTNode, field : String, index : Int32,
                                       literal : DiagnosticParsedLiteral,
                                       production : Indexable(DiagnosticLiteralProductionSegment),
                                       input : AcceptedCaptureInput) : Nil
      verify_input_bytes!(literal, production, owner_value(node, field, index), input)
    end

    def self.owner_value(node : ASTNode, field : String, index : Int32) : String
      raise ArgumentError.new("negative literal owner index") if index < 0
      case node
      when NamedArgument
        raise ArgumentError.new("invalid named argument literal field") unless node.class == NamedArgument && field == "name" && index == 0
        node.name
      when NamedTupleLiteral
        raise ArgumentError.new("invalid tuple literal field") unless node.class == NamedTupleLiteral && field == "entries.key"
        entry = node.entries[index]? || raise ArgumentError.new("unknown tuple literal index")
        entry.key
      when Arg
        raise ArgumentError.new("invalid external name literal field") unless node.class == Arg && field == "external_name" && index == 0
        node.external_name
      when FunDef
        raise ArgumentError.new("invalid foreign name literal field") unless node.class == FunDef && field == "real_name" && index == 0
        node.real_name
      when SymbolLiteral
        raise ArgumentError.new("invalid symbol literal field") unless node.class == SymbolLiteral && field == "value" && index == 0
        node.value
      when StringLiteral
        raise ArgumentError.new("invalid string literal field") unless node.class == StringLiteral && field == "value" && index == 0
        node.value
      when CharLiteral
        raise ArgumentError.new("invalid char literal field") unless node.class == CharLiteral && field == "value" && index == 0
        node.value.to_s
      when Require
        raise ArgumentError.new("invalid require literal field") unless node.class == Require && field == "string" && index == 0
        node.string
      when Asm
        raise ArgumentError.new("invalid asm literal field") unless node.class == Asm
        case field
        when "text"
          raise ArgumentError.new("invalid asm text index") unless index == 0
          node.text
        when "clobbers"
          clobbers = node.clobbers || raise ArgumentError.new("asm clobbers absent")
          clobbers[index]? || raise ArgumentError.new("unknown asm clobber index")
        else
          raise ArgumentError.new("invalid asm literal field")
        end
      when AsmOperand
        raise ArgumentError.new("invalid asm operand literal field") unless node.class == AsmOperand && field == "constraint" && index == 0
        node.constraint
      else
        raise ArgumentError.new("unsupported literal owner kind #{node.class}")
      end
    end

    def self.verify_input_bytes!(literal : DiagnosticParsedLiteral,
                                 productions : Indexable(DiagnosticLiteralProductionSegment),
                                 expected_value : String, input : AcceptedCaptureInput) : Nil
      unless literal.input_sha256 == input.input_sha256 &&
             literal.input_bytesize == input.input_bytesize &&
             literal.lexical_mode == input.lexical_mode
        raise ArgumentError.new("literal input identity mismatch")
      end
      raise ArgumentError.new("literal expansion requires expansion input binding") if literal.expansion
      max = DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
      if literal.decoded_base64.bytesize.to_i64 > max || expected_value.bytesize.to_i64 > max * 3 // 4 - 4
        raise ArgumentError.new("literal decoded value exceeds size limit")
      end
      unless literal.decoded_bytesize == expected_value.bytesize &&
             Base64.strict_encode(expected_value.to_slice) == literal.decoded_base64
        raise ArgumentError.new("literal decoded value mismatch")
      end
      raise ArgumentError.new("literal production evidence missing") if productions.empty?
      if productions.any? { |production| production.production.heredoc? }
        raise ArgumentError.new("heredoc production requires independent parser replay")
      end
      if literal.segments_count.to_i64 + productions.size.to_i64 > max // 64
        raise ArgumentError.new("literal evidence count exceeds size limit")
      end
      unless literal.segments_count == productions.size
        raise ArgumentError.new("literal constituent and production counts differ")
      end
      segment_index = 0
      literal.each_segment do |segment|
        unless input.matches_encoded_span?(segment.start_offset, segment.end_offset, segment.raw_base64)
          raise ArgumentError.new("literal constituent input bytes mismatch")
        end
        production = productions[segment_index]
        if production.production.percent_symbol_element? || production.production.percent_string_element?
          unless segment.start_offset >= production.start_offset && segment.end_offset <= production.end_offset
            raise ArgumentError.new("percent symbol constituent outside production")
          end
        elsif segment.start_offset != production.start_offset || segment.end_offset != production.end_offset
          raise ArgumentError.new("literal constituent and production span mismatch")
        end
        segment_index += 1
      end
      previous_end : Int32? = nil
      witness_total = 0_i64
      productions.each do |segment|
        unless input.matches_encoded_span?(segment.start_offset, segment.end_offset, segment.raw_base64)
          raise ArgumentError.new("literal production input bytes mismatch")
        end
        witness_total += segment.witnesses_count.to_i64
        raise ArgumentError.new("literal witnesses exceed size limit") if witness_total > max // 64
        verify_witnesses!(segment, previous_end, input.input_bytesize)
        previous_end = segment.end_offset
      end
    end

    private def self.verify_witnesses!(segment : DiagnosticLiteralProductionSegment, previous_end : Int32?,
                                       input_bytesize : Int32) : Nil
      if segment.production.string_piece?
        raise ArgumentError.new("string piece requires independent parser replay")
      end
      if segment.production.symbol_token? || segment.production.char_token? ||
         segment.production.magic_file? || segment.production.magic_dir?
        count = 0
        segment.each_witness do |witness|
          count += 1
          unless witness.kind.string_piece? && witness.start_offset == segment.start_offset &&
                 witness.end_offset == segment.end_offset
            raise ArgumentError.new("invalid symbol token witness")
          end
        end
        raise ArgumentError.new("invalid symbol token witness count") unless count == 1 && previous_end.nil?
        return
      end
      unless (segment.production.delimiter? && {"STRING", "REGEX", "COMMAND"}.includes?(segment.delimiter_kind)) ||
             (segment.production.percent_symbol_element? && segment.delimiter_kind == "SYMBOL_ARRAY") ||
             (segment.production.percent_string_element? && segment.delimiter_kind == "STRING_ARRAY")
        raise ArgumentError.new("invalid literal delimiter production")
      end
      if (segment.production.percent_symbol_element? || segment.production.percent_string_element?) && previous_end
        raise ArgumentError.new("percent symbol cannot be continued")
      end
      opener = false
      closer = false
      interpolation = false
      continuation = false
      cursor = segment.start_offset
      segment.each_witness do |witness|
        raise ArgumentError.new("literal witness lies outside input") if witness.end_offset > input_bytesize
        if witness.kind.continuation?
          unless previous_end && !opener && !continuation &&
                 witness.start_offset == previous_end && witness.end_offset == segment.start_offset
            raise ArgumentError.new("invalid literal continuation witness")
          end
          continuation = true
          next
        end
        unless witness.start_offset >= cursor && witness.end_offset <= segment.end_offset && !closer
          raise ArgumentError.new("unordered literal witness")
        end
        case witness.kind
        when .opener?
          raise ArgumentError.new("invalid literal opener witness") if opener || witness.start_offset != segment.start_offset
          opener = true
        when .closing_delimiter?
          unless opener && !interpolation && witness.end_offset == segment.end_offset
            raise ArgumentError.new("invalid literal closing witness")
          end
          closer = true
        when .string_piece?
          raise ArgumentError.new("string piece outside literal") unless opener && !interpolation
        when .interpolation_start?
          raise ArgumentError.new("invalid interpolation start witness") unless opener && !interpolation
          interpolation = true
        when .interpolation_end?
          raise ArgumentError.new("invalid interpolation end witness") unless interpolation
          interpolation = false
        else
          raise ArgumentError.new("unclassified literal witness")
        end
        cursor = witness.end_offset
      end
      unless opener && closer && !interpolation && (previous_end.nil? || continuation)
        raise ArgumentError.new("incomplete literal production witnesses")
      end
    end
  end

  # Checks recorded observations against one source input. Without a replay
  # journal and identity this is structural only and authorizes nothing. With
  # both, every span, origin and derived name must bind to the replay
  # (DiagnosticCaptureBinding.bind!). Legacy callers keep the byte-level mode.
  class DiagnosticRecordedEvidenceInputCheck
    MAX_DEPTH = 128
    @active = Set(UInt64).new
    @remaining : UInt64 = DiagnosticOrigin::MAX_UNFOLDED_BYTES
    @source : String

    def initialize(@input : AcceptedCaptureInput, @journal : DiagnosticReplayJournal? = nil,
                   @identity : DiagnosticModuleIdentity? = nil, structural : Set(UInt64)? = nil,
                   @literal_bundle : DiagnosticLiteralReplayAssociations? = nil)
      raise ArgumentError.new("bound evidence requires both a replay journal and module identity") unless @journal.nil? == @identity.nil?
      @source = @input.input
      @structural = structural || Set(UInt64).new
      @literal_fields = Set(DiagnosticCaptureFieldRef).new
      @scalar_verified = Set(UInt64).new
      @atom_fields = Set(DiagnosticCaptureFieldRef).new
    end

    def verify!(root : ASTNode) : Nil
      if bundle = @literal_bundle
        raise ArgumentError.new("literal replay input differs") unless bundle.input_key == @input.capture_key
        raise ArgumentError.new("literal replay journal differs") unless bundle.journal.same?(@journal)
        bundle.verify_graph!(root)
        reducer = DiagnosticLiteralReplay.new(@input, bundle.journal, bundle.folds, bundle.interpolations, bundle.literal_owners)
        owners = DiagnosticLiteralOwnerBinding.new(reducer, bundle.literal_owners)
        @scalar_verified = DiagnosticScalarGrammarReplay.new(@input, bundle.journal, owners, bundle.scalar_owners).verify!(root)
        @literal_fields = owners.verify!(root, @scalar_verified, bundle)
        @atom_fields = DiagnosticNumberLiteralBinding.from(@input, bundle).verify!(root) |
                       DiagnosticMacroLiteralBinding.from(@input, bundle).verify!(root)
      end
      verify_lib_order!(root, @input.input_bytesize, 0)
      visit(root, 0)
    end

    # D4, the order of lib funs. A fun's `fun` anchor lies after its own lib's name
    # and before the next lib's name, and one lib's anchors strictly increase. A
    # fun given another fun's origin breaks one of these, whatever name slots it
    # carries. Only Written anchors are ordered; Expanded origins have no source
    # position here, so they are not checked.
    private def verify_lib_order!(node : ASTNode, upper : Int32, depth : Int32) : Nil
      raise ArgumentError.new("recorded evidence exceeds depth limit") if depth > MAX_DEPTH
      case node
      when Expressions
        items = node.expressions
        items.each_with_index do |item, index|
          bound = upper
          if item.is_a?(LibDef)
            following = items[(index + 1)..].find { |sibling| sibling.is_a?(LibDef) }
            if following.is_a?(LibDef) && (next_lower = written_offset(following.name.diagnostic_origin))
              bound = next_lower
            end
          end
          verify_lib_order!(item, bound, depth + 1)
        end
      when LibDef
        verify_lib_fun_order!(node, upper)
        DiagnosticDirectChildFields.each(node) { |_, _, _, child| verify_lib_order!(child, upper, depth + 1) }
      else
        DiagnosticDirectChildFields.each(node) { |_, _, _, child| verify_lib_order!(child, upper, depth + 1) }
      end
    end

    private def verify_lib_fun_order!(lib_node : LibDef, upper : Int32) : Nil
      lower = written_offset(lib_node.name.diagnostic_origin)
      return unless lower
      body = lib_node.body
      items = body.is_a?(Expressions) ? body.expressions : [body] of ASTNode
      previous = lower
      items.each do |item|
        next unless item.is_a?(FunDef)
        anchor = written_offset(item.diagnostic_origin)
        next unless anchor
        raise ArgumentError.new("fun anchor lies outside its lib") unless lower < anchor && anchor < upper
        raise ArgumentError.new("fun anchors are out of source order") unless previous < anchor
        previous = anchor
      end
    end

    # The input offset of a fun's or lib's own Written anchor, through Synthetic
    # wrappers (which carry their parent's anchor). Nil for any other origin.
    private def written_offset(origin : DiagnosticOrigin?) : Int32?
      current = origin
      while current.is_a?(DiagnosticOrigin::Synthetic)
        current = current.parent_origin
      end
      current.is_a?(DiagnosticOrigin::Written) ? current.input_byte_offset : nil
    end

    private def bound? : Bool
      !@identity.nil?
    end

    private def charge(bytes : UInt64) : Nil
      raise ArgumentError.new("recorded evidence exceeds graph limit") if bytes > @remaining
      @remaining -= bytes
    end

    private def visit(node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("recorded evidence exceeds depth limit") if depth > MAX_DEPTH
      id = node.object_id
      raise ArgumentError.new("cyclic recorded evidence graph") unless @active.add?(id)
      begin
        # Each node has its own budget. The 8 MiB constant is unchanged.
        @remaining = DiagnosticOrigin::MAX_UNFOLDED_BYTES
        charge(256_u64)
        DiagnosticAstFieldSchema.validate_node_fields(node)
        if (identity = @identity) && node.is_a?(ModuleHeader)
          raise ArgumentError.new("multiple module headers") unless (header = identity.header) && header.same?(node)
        end
        if origin = node.diagnostic_origin
          check_structural_origin!(origin, depth)
        end
        if !node.is_a?(Arg) && node.diagnostic_external_explicit
          raise ArgumentError.new("external-name observation on non-argument node")
        end
        count = node.diagnostic_name_slots_count || 0
        charge(count.to_u64 * 64_u64)
        raise ArgumentError.new("recorded name evidence exceeds graph limit") if node.diagnostic_name_slots_graph_bytes > @remaining
        node.each_diagnostic_name_slot do |_, values|
          charge(values.size.to_u64 * 32_u64)
          values.each do |value|
            charge(value.graph_bytes)
            case value
            when DiagnosticNameValue::Observed
              token = value.source_token
              graph_depth = token.lexical_origin.graph_depth
              if binding = token.binding_origin
                graph_depth = Math.max(graph_depth, binding.graph_depth)
              end
              raise ArgumentError.new("recorded name evidence exceeds depth limit") if graph_depth.to_i64 + depth > MAX_DEPTH
              unless source_token_ok?(token)
                raise ArgumentError.new("recorded name token input mismatch")
              end
            when DiagnosticNameValue::Derived
              raise ArgumentError.new("derived name requires independently resolved ancestry") unless bound?
              bound_derived!(value.origin)
            else
              raise ArgumentError.new("unclassified recorded name evidence")
            end
          end
        end
        if bound?
          if node.is_a?(NumberLiteral) || node.is_a?(MacroLiteral)
            literal_bundle = @literal_bundle || raise ArgumentError.new("literal evidence requires journal literal binding")
            fields = node.is_a?(NumberLiteral) ? ["value", "kind"] : ["value"]
            fields.each do |field|
              raise ArgumentError.new("atomic literal field occurrence not bound") unless @atom_fields.includes?(literal_bundle.field_ref(node, field, 0))
            end
          end
          bundle = @literal_bundle
          literal_class = node.is_a?(StringLiteral) || node.is_a?(SymbolLiteral) || node.is_a?(CharLiteral) ||
                          node.is_a?(StringInterpolation) || node.is_a?(RegexLiteral)
          text_class = node.is_a?(Require) || node.is_a?(Asm) || node.is_a?(AsmOperand)
          if literal_class || text_class || (node.diagnostic_literal_names_count || 0) > 0 || (node.diagnostic_literal_productions_count || 0) > 0
            raise ArgumentError.new("literal evidence requires journal literal binding") unless bundle
            if text_class && !@scalar_verified.includes?(node.object_id)
              raise ArgumentError.new("scalar grammar binding missing")
            end
            node.each_diagnostic_literal_name do |key, _|
              unless @literal_fields.includes?(bundle.field_ref(node, key[0], key[1]))
                raise ArgumentError.new("literal field occurrence not bound")
              end
            end
          end
        else
          validate_literals(node)
        end
        verify_core_name_coverage!(node)
        DiagnosticDirectChildFields.each(node) { |_, _, _, child| visit(child, depth + 1) }
      ensure
        @active.delete(id)
      end
    end

    private def check_structural_origin!(origin : DiagnosticOrigin, depth : Int32) : Nil
      if origin.graph_depth.to_i64 + depth > MAX_DEPTH
        raise ArgumentError.new("structural origin exceeds depth limit")
      end
      charge(origin.graph_bytes)
      current = origin
      loop do
        case current
        when DiagnosticOrigin::Written
          unless written_identity_ok?(current)
            raise ArgumentError.new("structural origin input identity mismatch")
          end
          return
        when DiagnosticOrigin::Synthetic
          current = current.parent_origin
        when DiagnosticOrigin::Expanded
          raise ArgumentError.new("expanded structural origin requires resolved expansion ancestry")
        else
          raise ArgumentError.new("unclassified structural origin ancestry")
        end
      end
    end

    # Legacy mode: the input's own identity. Bound mode: the replay's identity,
    # chosen by offset. Both refuse an offset outside the input.
    private def written_identity_ok?(origin : DiagnosticOrigin::Written) : Bool
      identity = @identity
      return @input.matches_written_identity?(origin) unless identity
      offset = origin.input_byte_offset
      return false unless offset >= 0 && offset <= @input.input_bytesize
      origin.source_file == @input.original_file && origin.source_module == identity.expected_module(offset)
    end

    # A token is bound when the replay scanned its exact span with the same kind
    # and mode, its bytes match the input, and its origins resolve to the identity.
    private def source_token_ok?(token : DiagnosticSourceNameToken) : Bool
      return @input.matches_source_token?(token) unless bound?
      journal = @journal.not_nil!
      return false unless token.input_sha256 == @input.input_sha256 &&
                          token.input_bytesize == @input.input_bytesize &&
                          token.lexical_mode == @input.lexical_mode &&
                          token.input_start >= 0 && token.input_end > token.input_start &&
                          token.input_end <= @input.input_bytesize
      return false unless @source.byte_slice(token.input_start, token.input_end - token.input_start) == token.raw_text
      return false unless journal.scanned?(token)
      return false unless bound_written_origin?(token.lexical_origin)
      binding = token.binding_origin
      binding.nil? || bound_written_origin?(binding)
    end

    # Follows Synthetic parents to a Written origin that the identity accepts.
    # Expanded and any other ancestry is refused.
    private def bound_written_origin?(origin : DiagnosticOrigin) : Bool
      current = origin
      while current.is_a?(DiagnosticOrigin::Synthetic)
        current = current.parent_origin
      end
      current.is_a?(DiagnosticOrigin::Written) && written_identity_ok?(current)
    end

    private def bound_derived!(origin : DiagnosticOrigin::DerivedName) : Nil
      identity = @identity.not_nil!
      case origin.derivation_kind
      when "ModuleHeaderPath"   then verify_module_header_path!(origin, identity)
      when "ImplicitModuleSelf" then verify_implicit_module_self!(origin, identity)
      when "StructuralName"
        raise ArgumentError.new("structural witness is not verified") unless @structural.includes?(origin.object_id)
      else
        raise ArgumentError.new("derived name #{origin.derivation_kind} has no journal binding")
      end
    end

    private def verify_module_header_path!(origin : DiagnosticOrigin::DerivedName,
                                           identity : DiagnosticModuleIdentity) : Nil
      header = identity.header_origin || raise ArgumentError.new("module header path without a module header")
      raise ArgumentError.new("module header path origin differs") unless origin.module_header_origin == header
      segments = origin.source_segments
      raise ArgumentError.new("module header path segments differ") unless segments.map(&.raw_text) == identity.header_segments
      segments.each do |token|
        raise ArgumentError.new("module segment is not a scanned token") unless source_token_ok?(token)
      end
      raise ArgumentError.new("module header path package differs") unless origin.package_name == identity.package
      index = origin.result_index || raise ArgumentError.new("module header path lacks result index")
      segment = Parser.iyi_package_segments(identity.package, identity.header_segments)[index]?
      raise ArgumentError.new("module header path index out of range") unless segment
      raise ArgumentError.new("module header path rendering differs") unless origin.rendered_text == segment.camelcase
    end

    private def verify_implicit_module_self!(origin : DiagnosticOrigin::DerivedName,
                                             identity : DiagnosticModuleIdentity) : Nil
      header = identity.header_origin || raise ArgumentError.new("implicit module self without a module header")
      raise ArgumentError.new("implicit module self origin differs") unless origin.module_header_origin == header
      raise ArgumentError.new("implicit module self rendering differs") unless origin.rendered_text == "self"
    end

    # Actual field values drive this check. This deliberately refuses fields
    # whose source-to-field mapping has not been classified here.
    private def verify_core_name_coverage!(node : ASTNode) : Nil
      slot_count = node.diagnostic_name_slots_count || 0
      literal_count = node.diagnostic_literal_names_count || 0
      charge(slot_count.to_u64 * 64_u64 + literal_count.to_u64 * 64_u64)
      slots = {} of DiagnosticNameSlot => Indexable(DiagnosticNameValue)
      literal_keys = Set({String, Int32}).new
      used_slots = Set(DiagnosticNameSlot).new
      node.each_diagnostic_name_slot { |slot, values| slots[slot] = values }
      node.each_diagnostic_literal_name { |key, _| literal_keys.add(key) }
      bound_indices = {} of String => Int32
      variables = case node
                  when Def     then node.free_vars
                  when ImplDef then node.type_vars
                  else              nil
                  end
      if variables
        charge(variables.size.to_u64 * 64_u64)
        variables.each_with_index do |name, index|
          raise ArgumentError.new("duplicate bound-variable identity") if bound_indices.has_key?(name)
          bound_indices[name] = index
        end
      end
      has_assoc_projection = validate_assoc_projection!(node)
      where_index = 0
      DiagnosticDirectNameFields.each(node) do |field, index, key, expected|
        slot : DiagnosticNameSlot? = nil
        literal_key : {String, Int32}? = nil
        reuse_slot = false
        case node
        when Path
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::PathSegment, index.not_nil!) if field == "names"
        when NamedArgument
          if field == "name"
            literal_key = {"name", 0}
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry)
          end
        when NamedTupleLiteral
          if field == "entries.key"
            literal_key = {"entries.key", index.not_nil!}
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry, index.not_nil!)
          end
        when Arg
          # An enum member is an Arg whose internal name lives in the EnumMember slot
          # (parser.cr enum body). Copy-time validation already refuses both slots at once.
          internal = slots.has_key?(DiagnosticNameSlot.new(DiagnosticNameSlotKind::EnumMember)) ?
                     DiagnosticNameSlot.new(DiagnosticNameSlotKind::EnumMember) :
                     DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
          if field == "name"
            slot = internal
          elsif field == "external_name"
            if !node.diagnostic_external_explicit
              external = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ExternalName)
              if expected != node.name || slots.has_key?(external) || literal_keys.includes?({"external_name", 0})
                raise ArgumentError.new("invalid implicit external-name observation")
              end
              values = slots[internal]? || raise ArgumentError.new("implicit external name lacks internal evidence")
              verify_slot_value!(values, expected)
              next
            end
            literal_key = {"external_name", 0}
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ExternalName)
          end
        when FunDef
          if field == "name"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
            if (journal = @journal)
              name_values = slots[DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)]? || raise ArgumentError.new("missing source evidence for FunDef.name")
              name_token = fun_name_token(name_values) || raise ArgumentError.new("fun name is not an observed token")
              raise ArgumentError.new("fun name is not a scanned token") unless journal.scanned?(name_token)
              verify_fun_name_position!(node, journal, name_token)
            end
          elsif field == "real_name"
            external = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ExternalName)
            literal = {"real_name", 0}
            has_external = slots.has_key?(external)
            has_literal = literal_keys.includes?(literal)
            raise ArgumentError.new("ambiguous fun real name evidence") if has_external && has_literal
            name_values = slots[DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)]? || raise ArgumentError.new("fun real name lacks name evidence")
            if (journal = @journal)
              name_token = fun_name_token(name_values) || raise ArgumentError.new("fun name is not an observed token")
              raise ArgumentError.new("fun name is not a scanned token") unless journal.scanned?(name_token)
              verify_fun_name_position!(node, journal, name_token)
              following = fun_next_token(journal, name_token.input_end)
              if has_external || has_literal
                raise ArgumentError.new("explicit fun real name lacks '=' evidence") unless following
                raise ArgumentError.new("explicit fun real name lacks '=' evidence") unless following.token_text == "="
                value_token = fun_next_token(journal, following.input_end) || raise ArgumentError.new("explicit fun real name lacks a value token")
                if has_external
                  real_token = fun_name_token(slots[external]) || raise ArgumentError.new("explicit fun real name is not an observed token")
                  raise ArgumentError.new("explicit fun real name is not a scanned token") unless journal.scanned?(real_token)
                  raise ArgumentError.new("explicit fun real name is not the token after '='") unless real_token.input_start == value_token.input_start && real_token.input_end == value_token.input_end
                  slot = external
                else
                  raise ArgumentError.new("quoted fun real name lacks its opening delimiter") unless value_token.token_kind == "DELIMITER_START"
                  literal_key = literal
                  slot = external
                end
              else
                raise ArgumentError.new("invalid implicit foreign-name observation") unless expected == node.name
                raise ArgumentError.new("implicit fun real name lacks evidence") if following && following.token_text == "="
                verify_slot_value!(name_values, expected)
                next
              end
            elsif has_external
              # Legacy byte-level mode: the token text is checked against the name. Nothing is authorized.
              slot = external
            elsif has_literal
              literal_key = literal
              slot = external
            else
              # Legacy implicit: the source name must equal the real name. Only the bound path proves that no `=` follows.
              raise ArgumentError.new("invalid implicit foreign-name observation") unless expected == node.name
              verify_slot_value!(name_values, expected)
              next
            end
          end
        when SymbolLiteral
          literal_key = {"value", 0} if field == "value"
        when Def
          if field == "name"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
          elsif field == "free_vars"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, index.not_nil!)
          elsif field == "free_var_bounds.key"
            variable_index = bound_indices[key.not_nil!]? || raise ArgumentError.new("free-variable bound lacks original declaration")
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, variable_index)
            reuse_slot = true
          elsif field == "where_bounds.key"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::WhereVariable, where_index)
            where_index += 1
          end
        when ModuleHeader
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ModuleSegment, index.not_nil!) if field == "path"
        when ImportDecl, UsingDecl
          if field == "path"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ModuleSegment, index.not_nil!)
          elsif field == "names"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::NamedEntry, index.not_nil!)
          end
        when ClassDef, ModuleDef
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, index.not_nil!) if field == "type_vars"
        when TraitDef
          if field == "type_vars"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, index.not_nil!)
          elsif field == "assoc_types" && has_assoc_projection
            next
          end
        when ImplDef
          if field == "type_vars"
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, index.not_nil!)
          elsif field == "type_var_bounds.key"
            variable_index = bound_indices[key.not_nil!]? || raise ArgumentError.new("impl bound lacks original declaration")
            slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter, variable_index)
            reuse_slot = true
          elsif field == "assoc_types.key" && has_assoc_projection
            next
          end
        when Var, InstanceVar, ClassVar, Global, ReadInstanceVar, Call, Macro, RespondsTo,
             ProcPointer, TypeDef, CStructOrUnionDef, MacroVar
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary) if field == "name"
        when AssocTypeDecl
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::TypeParameter) if field == "name"
        when OpAssign
          slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary) if field == "op"
        end
        if literal_key && literal_keys.includes?(literal_key)
          raise ArgumentError.new("ambiguous literal and token name evidence") if slot && slots.has_key?(slot)
          next
        end
        unless slot
          raise ArgumentError.new("unclassified source-to-name mapping #{node.class}.#{field}")
        end
        values = slots[slot]? || raise ArgumentError.new("missing source evidence for #{node.class}.#{field}")
        if reuse_slot
          raise ArgumentError.new("bound name lacks prior declaration evidence") unless used_slots.includes?(slot)
        else
          raise ArgumentError.new("name source evidence reused across fields") unless used_slots.add?(slot)
        end
        verify_slot_value!(values, expected)
      end

      # `Self` has no name field. Its Primary slot, if any, may only hold "self".
      if node.class.name.rpartition("::")[2] == "Self"
        primary = DiagnosticNameSlot.new(DiagnosticNameSlotKind::Primary)
        if values = slots[primary]?
          verify_slot_value!(values, "self")
          used_slots.add(primary)
        end
      end
      slots.each_key do |slot|
        raise ArgumentError.new("unbound name evidence slot #{slot.kind}:#{slot.index}") unless used_slots.includes?(slot)
      end
    end

    # The name token must be the first non-trivia journal token after this FunDef's own
    # written `fun` keyword. A name token from another fun is refused here.
    private def verify_fun_name_position!(node : FunDef, journal : DiagnosticReplayJournal, name_token : DiagnosticSourceNameToken) : Nil
      written = node.diagnostic_origin
      while written.is_a?(DiagnosticOrigin::Synthetic)
        written = written.parent_origin
      end
      raise ArgumentError.new("fun name lacks a written fun anchor") unless written.is_a?(DiagnosticOrigin::Written)
      raise ArgumentError.new("fun name lacks a written fun anchor") unless written.valid_for_anchor?("FunDef", "keyword")
      start = written.input_byte_offset
      raise ArgumentError.new("fun name lacks a written fun anchor") unless journal.scanned_span?(start, start + 3, "IDENT", "fun", @input.lexical_mode)
      first = fun_next_token(journal, start + 3) || raise ArgumentError.new("fun name is not the token after its fun keyword")
      unless first.input_start == name_token.input_start && first.input_end == name_token.input_end && first.token_text == name_token.raw_text
        raise ArgumentError.new("fun name is not the token after its fun keyword")
      end
    end

    # The observed token behind a name slot that holds exactly one token.
    private def fun_name_token(values : Indexable(DiagnosticNameValue)) : DiagnosticSourceNameToken?
      return nil unless values.size == 1
      observed = values[0].as?(DiagnosticNameValue::Observed) || return nil
      observed.source_token
    end

    # The first journal entry at or after offset that is not trivia.
    private def fun_next_token(journal : DiagnosticReplayJournal, offset : Int32) : DiagnosticRenderedToken?
      journal.entries.select { |entry| entry.input_start >= offset && !{"SPACE", "NEWLINE", "COMMENT", "EOF"}.includes?(entry.token_kind) }.min_by? { |entry| entry.input_start }
    end

    # The parser derives these summaries only from direct body declarations,
    # preserving declaration order and, for impls, the exact value node.
    private def validate_assoc_projection!(node : ASTNode) : Bool
      body = case node
             when TraitDef then node.body
             when ImplDef  then node.body
             else               return false
             end
      declarations = [] of AssocTypeDecl
      case body
      when AssocTypeDecl
        charge(128_u64)
        declarations << body
      when Expressions
        body.expressions.each do |child|
          next unless child.is_a?(AssocTypeDecl)
          charge(128_u64)
          declarations << child
        end
      end
      if declarations.empty?
        case node
        when TraitDef, ImplDef
          raise ArgumentError.new("unexpected empty associated-type projection") unless node.assoc_types.nil?
        else
          raise ArgumentError.new("unclassified associated-type owner")
        end
        return false
      end
      names = Set(String).new
      declarations.each do |declaration|
        raise ArgumentError.new("associated type not recorded in body") unless declaration.in_type_body?
        raise ArgumentError.new("duplicate associated type") unless names.add?(declaration.name)
      end
      case node
      when TraitDef
        projected = node.assoc_types || raise ArgumentError.new("trait associated-type projection missing")
        raise ArgumentError.new("trait associated-type projection size mismatch") unless projected.size == declarations.size
        declarations.each_with_index do |declaration, index|
          unless declaration.value.nil? && projected[index] == declaration.name
            raise ArgumentError.new("trait associated-type projection mismatch")
          end
        end
      when ImplDef
        projected = node.assoc_types || raise ArgumentError.new("impl associated-type projection missing")
        raise ArgumentError.new("impl associated-type projection size mismatch") unless projected.size == declarations.size
        index = 0
        projected.each do |name, value|
          declaration = declarations[index]
          unless name == declaration.name && (source = declaration.value) && value.same?(source)
            raise ArgumentError.new("impl associated-type projection mismatch")
          end
          index += 1
        end
      end
      true
    end

    private def verify_slot_value!(values : Indexable(DiagnosticNameValue), expected : String) : Nil
      raise ArgumentError.new("empty name evidence") if values.empty?
      bytes = expected.to_slice
      offset = 0
      values.each do |value|
        part = value.rendered_text.to_slice
        if part.size > bytes.size - offset || bytes[offset, part.size] != part
          raise ArgumentError.new("name field differs from source evidence")
        end
        offset += part.size
      end
      raise ArgumentError.new("name field differs from source evidence") unless offset == bytes.size
    end

    private def validate_literals(node : ASTNode) : Nil
      names_count = node.diagnostic_literal_names_count
      production_count = node.diagnostic_literal_productions_count
      if (node.class == StringLiteral || node.class == SymbolLiteral) && names_count.nil?
        raise ArgumentError.new("literal value lacks source or construction evidence")
      end
      return if names_count.nil? && production_count.nil?
      unless names_count && production_count && names_count == production_count
        raise ArgumentError.new("literal observations and productions differ in presence or count")
      end
      charge(names_count.to_u64 * 128_u64)
      if node.diagnostic_literal_names_encoded_bytes > @remaining ||
         node.diagnostic_literal_productions_raw_bytes > @remaining
        raise ArgumentError.new("literal evidence exceeds graph limit")
      end
      names = [] of Tuple(Tuple(String, Int32), DiagnosticParsedLiteral)
      productions = [] of Tuple(Tuple(String, Int32), Array(DiagnosticLiteralProductionSegment))
      node.each_diagnostic_literal_name { |key, value| names << {key, value} }
      node.each_diagnostic_literal_production { |key, value| productions << {key, value.to_a} }
      names.sort_by! { |entry| entry[0] }
      productions.sort_by! { |entry| entry[0] }
      names.each_with_index do |(key, literal), index|
        production_key, segments = productions[index]
        raise ArgumentError.new("literal owner evidence keys differ") unless key == production_key
        charge(literal.decoded_base64.bytesize.to_u64)
        segments.each { |segment| charge(segment.raw_base64.bytesize.to_u64) }
        DiagnosticLiteralInputChecks.verify_owner_observation!(node, key[0], key[1], literal, segments, @input)
      end
    end
  end
end

module Iyi
  # A coordinate in one accepted parser input, not an assertion that the
  # coordinate resolves. Only the frozen capture registry can establish that.
  class DiagnosticCaptureFieldRef
    @capture_id : String
    @owner_path_json : String
    @field_tag : String
    getter index : Int32?
    @map_key : String?

    def initialize(@capture_id : String, @owner_path_json : String, @field_tag : String,
                   @index : Int32? = nil, @map_key : String? = nil)
      unless @capture_id.bytesize == 64 && @capture_id.each_byte.all? { |b| (48_u8..57_u8).includes?(b) || (97_u8..102_u8).includes?(b) }
        raise ArgumentError.new("invalid capture input identity")
      end
      if @owner_path_json.bytesize.to_i64 + @field_tag.bytesize.to_i64 +
         (@map_key.try(&.bytesize) || 0).to_i64 > DiagnosticOrigin::MAX_UNFOLDED_BYTES.to_i64
        raise ArgumentError.new("capture field coordinate exceeds size limit")
      end
      raise ArgumentError.new("empty capture field tag") if @field_tag.empty?
      raise ArgumentError.new("invalid capture field index") if @index.try { |i| i < 0 }
      raise ArgumentError.new("ambiguous capture field coordinate") if @index && @map_key
      raise ArgumentError.new("invalid capture owner path") unless JSON.parse(@owner_path_json).as_a?
      @capture_id = String.new(@capture_id.to_slice)
      @owner_path_json = String.new(@owner_path_json.to_slice)
      @field_tag = String.new(@field_tag.to_slice)
      @map_key = @map_key.try { |value| String.new(value.to_slice) }
    end

    def capture_id : String
      String.new(@capture_id.to_slice)
    end

    def owner_path_json : String
      String.new(@owner_path_json.to_slice)
    end

    def field_tag : String
      String.new(@field_tag.to_slice)
    end

    def map_key : String?
      @map_key.try { |value| String.new(value.to_slice) }
    end

    def_equals_and_hash @capture_id, @owner_path_json, @field_tag, @index, @map_key
  end

  # Coordinates identify the first framed occurrence, not authority. A consumer
  # must still bind the capture against its ledger and replay evidence.
  module DiagnosticCaptureRefs
    alias Step = {String, Int32?, String?}

    def self.stamp!(root : ASTNode, capture_key : String) : Nil
      visited = Set(UInt64).new
      active = Set(UInt64).new
      path = [] of Step
      visit(root, DiagnosticCaptureFieldRef.new(capture_key, "[]", "root"), capture_key, path, visited, active)
    end

    private def self.visit(node : ASTNode, ref : DiagnosticCaptureFieldRef, capture_key : String,
                           path : Array(Step), visited : Set(UInt64), active : Set(UInt64)) : Nil
      raise ArgumentError.new("AST inventory exceeds depth limit") if path.size > DiagnosticAstFrameStream::MAX_DEPTH
      raise ArgumentError.new("cyclic AST inventory") if active.includes?(node.object_id)
      return unless visited.add?(node.object_id)
      active.add(node.object_id)
      begin
        node.diagnostic_capture_ref = ref
        DiagnosticDirectChildFields.each(node) do |field, index, key, child|
          raise ArgumentError.new("AST inventory exceeds depth limit") if path.size + 1 > DiagnosticAstFrameStream::MAX_DEPTH
          raise ArgumentError.new("cyclic AST inventory") if active.includes?(child.object_id)
          next if visited.includes?(child.object_id)
          child_ref = DiagnosticCaptureFieldRef.new(capture_key, path.to_json, field, index, key)
          path << {field, index, key.try { |value| Base64.strict_encode(value) }}
          begin
            visit(child, child_ref, capture_key, path, visited, active)
          ensure
            path.pop
          end
        end
      ensure
        active.delete(node.object_id)
      end
    end
  end

  # The replay's own lexical journal, indexed by start offset. Membership here
  # is the only evidence that a span was scanned. Byte equality alone is not.
  class DiagnosticReplayJournal
    @entries : Array(DiagnosticRenderedToken)
    @by_start : Hash(Int32, Array(DiagnosticRenderedToken))
    @by_end : Hash(Int32, Array(DiagnosticRenderedToken))

    def initialize(entries : Array(DiagnosticRenderedToken))
      @entries = entries.map { |entry| copy_entry(entry) }
      @by_start = {} of Int32 => Array(DiagnosticRenderedToken)
      @by_end = {} of Int32 => Array(DiagnosticRenderedToken)
      @entries.each do |entry|
        (@by_start[entry.input_start] ||= [] of DiagnosticRenderedToken) << entry
        (@by_end[entry.input_end] ||= [] of DiagnosticRenderedToken) << entry
      end
    end

    def entries : Array(DiagnosticRenderedToken)
      @entries.map { |entry| copy_entry(entry) }
    end

    def starts_at(start : Int32) : Array(DiagnosticRenderedToken)
      @by_start[start]?.try { |entries| entries.map { |entry| copy_entry(entry) } } || [] of DiagnosticRenderedToken
    end

    def ends_at(finish : Int32) : Array(DiagnosticRenderedToken)
      @by_end[finish]?.try { |entries| entries.map { |entry| copy_entry(entry) } } || [] of DiagnosticRenderedToken
    end

    # Ordinals belong to the parser's fresh replay journal, not to serialized
    # claims. Resolve them before using a parser association as a boundary.
    def entry!(reference : DiagnosticReplayTokenRef) : DiagnosticRenderedToken
      ordinal = reference.ordinal
      raise ArgumentError.new("invalid replay token reference") if ordinal < 0
      entry = @entries[ordinal]? || raise ArgumentError.new("invalid replay token reference")
      copy_entry(entry)
    end

    private def unique_at(start : Int32) : DiagnosticRenderedToken?
      entries = @by_start[start]?
      return nil unless entries
      first = entries.first?
      entries.each do |entry|
        raise ArgumentError.new("ambiguous scanned token") unless entry == first
      end
      first
    end

    def entry_at!(start : Int32, mode : String) : DiagnosticRenderedToken
      entry = unique_at(start) || raise ArgumentError.new("literal span is not tiled by scanned tokens")
      raise ArgumentError.new("literal token mode differs") unless entry.lexical_mode == mode
      copy_entry(entry)
    end

    def scanned?(token : DiagnosticSourceNameToken) : Bool
      scanned_span?(token.input_start, token.input_end, token.token_kind, token.raw_text, token.lexical_mode)
    end

    def scanned_span?(start : Int32, finish : Int32, kind : String, raw : String, mode : String) : Bool
      (@by_start[start]? || [] of DiagnosticRenderedToken).any? do |entry|
        entry.input_end == finish && entry.token_kind == kind && entry.token_text == raw && entry.lexical_mode == mode
      end
    end

    # Return the lexer's unique observation for a witness, never an observation
    # selected merely because its bytes happen to match. Repeated identical
    # observations are possible when the lexer revisits a token.
    def literal_entry!(start : Int32, finish : Int32, kind : String, mode : String) : DiagnosticRenderedToken
      entry = unique_at(start) || raise ArgumentError.new("literal witness is not a scanned token")
      unless entry.input_end == finish && entry.token_kind == kind && entry.lexical_mode == mode
        raise ArgumentError.new("literal witness is not a scanned token")
      end
      copy_entry(entry)
    end

    private def copy_entry(entry : DiagnosticRenderedToken) : DiagnosticRenderedToken
      delimiter = entry.delimiter.try do |state|
        DiagnosticRenderedDelimiter.new(String.new(state.kind.to_slice), String.new(state.nest.to_slice),
          String.new(state.end_delimiter.to_slice), state.allow_escapes, state.heredoc_indent)
      end
      DiagnosticRenderedToken.new(entry.input_start, entry.input_end, String.new(entry.token_kind.to_slice),
        String.new(entry.token_text.to_slice), String.new(entry.lexical_mode.to_slice),
        entry.value_base64.try { |value| String.new(value.to_slice) }, delimiter,
        entry.passed_backslash_newline, entry.invalid_escape, entry.line,
        entry.number_kind.try { |kind| String.new(kind.to_slice) })
    end

    # Derive an atomic value from the lexer; callers must also bind its owner.
    def literal_atom!(production : DiagnosticLiteralProductionSegment, mode : String) : String
      kind = case production.production
             when .symbol_token? then "SYMBOL"
             when .char_token?   then "CHAR"
             when .magic_file?   then "__FILE__"
             when .magic_dir?    then "__DIR__"
             when .string_piece? then "STRING"
             else
               raise ArgumentError.new("literal production is not atomic")
             end
      witnesses = production.witnesses
      unless witnesses.size == 1 && witnesses[0].kind.string_piece? &&
             witnesses[0].start_offset == production.start_offset && witnesses[0].end_offset == production.end_offset
        raise ArgumentError.new("invalid atomic literal witness")
      end
      entry = literal_entry!(production.start_offset, production.end_offset, kind, mode)
      if production.production.string_piece?
        state = entry.delimiter
        unless state && state.kind == production.delimiter_kind && state.nest == production.nest &&
               state.end_delimiter == production.end_delimiter && state.allow_escapes == production.allow_escapes
          raise ArgumentError.new("literal delimiter state differs from scanned token")
        end
        raise ArgumentError.new("literal string token has an invalid escape") if entry.invalid_escape
      end
      encoded = entry.value_base64 || raise ArgumentError.new("literal scanned token lacks a value")
      String.new(DiagnosticRenderedToken.decode_value(encoded,
        DiagnosticRenderedToken.value_bound(entry.token_kind, entry.token_text)))
    end

    # Cover a grammar gap only with observations emitted by the lexer. Skipped
    # comments and pragmas are observations, not grammar tokens.
    def literal_trivia!(start : Int32, finish : Int32, mode : String, allow_newline : Bool) : Nil
      raise ArgumentError.new("invalid trivia span") unless start >= 0 && finish >= start
      cursor = start
      while cursor < finish
        entry = unique_at(cursor) || raise ArgumentError.new("unwitnessed grammar gap")
        permitted = entry.token_kind == "SPACE" ||
                    (allow_newline && entry.token_kind == "NEWLINE") ||
                    {"SKIPPED_COMMENT", "SKIPPED_DOC_COMMENT", "SKIPPED_LOC_PRAGMA"}.includes?(entry.token_kind)
        unless permitted && entry.lexical_mode == mode && entry.input_end > cursor && entry.input_end <= finish
          raise ArgumentError.new("unwitnessed grammar gap")
        end
        cursor = entry.input_end
      end
    end
  end

  # Snapshot of one completed replay, before callers can mutate its tree.
  # It supplies evidence to binding; constructing one is not authority.
  class DiagnosticLiteralReplayAssociations
    record Edge, field : String, index : Int32?, key : String?, child : ASTNode
    record NodeEdges, owner : ASTNode, edges : Array(Edge)

    def input_key : String
      String.new(@input_key.to_slice)
    end
    getter journal : DiagnosticReplayJournal

    @input_key : String
    @mode : String
    @literal_owners : Array(DiagnosticLiteralOwnerObservation)
    @numbers : Array(DiagnosticNumberObservation)
    @signed_numbers : Array(DiagnosticSignedNumberObservation)
    @macro_literals : Array(DiagnosticMacroLiteralObservation)
    @scalar_owners : Array(DiagnosticScalarGrammarObservation)
    @folds : Array(DiagnosticFoldedStringObservation)
    @interpolations : Array(DiagnosticInterpolationObservation)
    @wrappers : Array(DiagnosticInterpolationWrapperObservation)
    @wrapper_pieces : Array(DiagnosticInterpolationPieceObservation)
    @transfers : Array(DiagnosticLiteralTransferObservation)
    @heredoc_groups : Array(DiagnosticHeredocGroupObservation)
    @percent_groups : Array(DiagnosticPercentGroupObservation)
    @percent_elements : Array(DiagnosticPercentElementObservation)
    @payloads : Array(DiagnosticLiteralPayloadObservation)
    @regex_options : Array(DiagnosticRegexOptionsObservation)
    @graph : Hash(UInt64, NodeEdges)
    @coordinates : Hash(UInt64, String)
    @path : Array(DiagnosticCaptureRefs::Step)
    @active : Set(UInt64)

    def initialize(input : AcceptedCaptureInput, @journal : DiagnosticReplayJournal, parser : Parser, @root : ASTNode)
      @input_key = input.capture_key
      @mode = input.lexical_mode
      @literal_owners = parser.diagnostic_literal_owner_observations.map { |item| copy_owner(item) }
      @numbers = parser.diagnostic_number_observations
      @signed_numbers = parser.diagnostic_signed_number_observations
      @macro_literals = parser.diagnostic_macro_literal_observations
      @scalar_owners = parser.diagnostic_scalar_grammar_observations
      @folds = parser.diagnostic_folded_string_observations
      @interpolations = parser.diagnostic_interpolation_observations
      @wrappers = parser.diagnostic_interpolation_wrapper_observations
      @wrapper_pieces = parser.diagnostic_interpolation_piece_observations
      @transfers = parser.diagnostic_literal_transfer_observations
      @heredoc_groups = parser.diagnostic_heredoc_group_observations
      @percent_groups = parser.diagnostic_percent_group_observations
      @percent_elements = parser.diagnostic_percent_element_observations
      @payloads = parser.diagnostic_literal_payload_observations
      @regex_options = parser.diagnostic_regex_options_observations
      @graph = {} of UInt64 => NodeEdges
      @coordinates = {} of UInt64 => String
      @path = [] of DiagnosticCaptureRefs::Step
      @active = Set(UInt64).new
      freeze_graph!(@root, 0)
    end

    def literal_owners : Array(DiagnosticLiteralOwnerObservation)
      @literal_owners.map { |item| copy_owner(item) }
    end

    def scalar_owners : Array(DiagnosticScalarGrammarObservation)
      @scalar_owners.dup
    end

    def folds : Array(DiagnosticFoldedStringObservation)
      @folds.dup
    end

    def interpolations : Array(DiagnosticInterpolationObservation)
      @interpolations.dup
    end

    def wrappers : Array(DiagnosticInterpolationWrapperObservation)
      @wrappers.map { |item| DiagnosticInterpolationWrapperObservation.new(item.owner, item.delimiters.dup, item.expressions.dup) }
    end

    def wrapper_pieces : Array(DiagnosticInterpolationPieceObservation)
      @wrapper_pieces.dup
    end

    def transfers : Array(DiagnosticLiteralTransferObservation)
      @transfers.dup
    end

    def heredoc_groups : Array(DiagnosticHeredocGroupObservation)
      @heredoc_groups.map { |item| DiagnosticHeredocGroupObservation.new(item.placeholder, item.opener, item.body, item.close, item.results.dup) }
    end

    def percent_groups : Array(DiagnosticPercentGroupObservation)
      @percent_groups.map { |item| DiagnosticPercentGroupObservation.new(item.owner, item.opener, item.close, item.elements.dup) }
    end

    def percent_elements : Array(DiagnosticPercentElementObservation)
      @percent_elements.dup
    end

    def payloads : Array(DiagnosticLiteralPayloadObservation)
      @payloads.dup
    end

    def regex_options : Array(DiagnosticRegexOptionsObservation)
      @regex_options.map { |item| DiagnosticRegexOptionsObservation.new(item.owner, item.opener, item.close, item.after, item.modifiers.dup) }
    end

    def numbers : Array(DiagnosticNumberObservation)
      @numbers.dup
    end

    def signed_numbers : Array(DiagnosticSignedNumberObservation)
      @signed_numbers.dup
    end

    def macro_literals : Array(DiagnosticMacroLiteralObservation)
      @macro_literals.dup
    end

    # True only when the frozen snapshot holds this exact object, not an equal one.
    def frozen?(node : ASTNode) : Bool
      snapshot = @graph[node.object_id]?
      return false unless snapshot
      snapshot.owner.same?(node)
    end

    # Yields each frozen owner with a copy of its edges, in the frozen order.
    def each_frozen(& : ASTNode, Array(Edge) ->)
      @graph.each_value { |snapshot| yield snapshot.owner, snapshot.edges.dup }
    end

    def field_ref(owner : ASTNode, field : String, index : Int32) : DiagnosticCaptureFieldRef
      snapshot = @graph[owner.object_id]? || raise ArgumentError.new("literal owner is outside replay graph")
      raise ArgumentError.new("literal owner is outside replay graph") unless snapshot.owner.same?(owner)
      DiagnosticCaptureFieldRef.new(@input_key, @coordinates[owner.object_id], field, index)
    end

    def verify_graph!(root : ASTNode) : Nil
      raise ArgumentError.new("literal replay root differs") unless @root.same?(root)
      @graph.each_value do |snapshot|
        current = [] of Edge
        DiagnosticDirectChildFields.each(snapshot.owner) do |field, index, key, child|
          current << Edge.new(field, index, key, child)
        end
        raise ArgumentError.new("literal replay graph differs") unless current.size == snapshot.edges.size
        current.each_with_index do |edge, index|
          expected = snapshot.edges[index]
          unless edge.field == expected.field && edge.index == expected.index && edge.key == expected.key &&
                 edge.child.same?(expected.child)
            raise ArgumentError.new("literal replay graph differs")
          end
        end
      end
    end

    def verify_relationships! : Nil
      interpolation_owners = Set(UInt64).new
      @wrappers.each do |wrapper|
        raise ArgumentError.new("duplicate interpolation wrapper") unless interpolation_owners.add?(wrapper.owner.object_id)
      end
      @heredoc_groups.each do |group|
        raise ArgumentError.new("duplicate interpolation wrapper") unless interpolation_owners.add?(group.placeholder.object_id)
      end
      @graph.each_value do |snapshot|
        if snapshot.owner.is_a?(StringInterpolation) && !interpolation_owners.includes?(snapshot.owner.object_id)
          raise ArgumentError.new("interpolation wrapper association missing")
        end
      end
      @wrapper_pieces.each do |piece|
        matches = @wrappers.select { |wrapper| wrapper.owner.same?(piece.owner) }
        unless matches.size == 1 && piece.index >= 0 && piece.index < matches[0].expressions.size &&
               matches[0].expressions[piece.index].same?(piece.expression)
          raise ArgumentError.new("orphan interpolation piece association")
        end
      end
      @percent_elements.each do |element|
        count = @percent_groups.count { |group| group.elements.any?(&.same?(element.owner)) }
        raise ArgumentError.new("orphan percent element association") unless count == 1
      end
      @wrappers.each { |wrapper| verify_wrapper!(wrapper) }
      @transfers.each do |transfer|
        source = @literal_owners.select do |item|
          item.owner.same?(transfer.source) && item.field == "value" && item.index == 0
        end
        target = @literal_owners.select do |item|
          item.owner.same?(transfer.target) && item.field == transfer.field && item.index == transfer.index
        end
        unless source.size == 1 && target.size == 1 && source[0].ranges == target[0].ranges
          raise ArgumentError.new("literal transfer association differs")
        end
        from = source[0].productions
        to = target[0].productions
        unless from && to && from.size == to.size &&
               from.zip(to).all? { |pair| same_literal_production?(pair[0], pair[1]) }
          raise ArgumentError.new("literal transfer association differs")
        end
      end
      @interpolations.each do |item|
        opener = relationship_token!(item.open, "INTERPOLATION_START")
        closer = relationship_token!(item.close, "}")
        first = @journal.entry!(item.expression_first)
        unless first.lexical_mode == @mode && opener.input_end <= first.input_start &&
               first.input_end <= closer.input_start
          raise ArgumentError.new("interpolation association differs")
        end
        verify_interpolation_prefix!(item, opener, first)
      end
      @folds.each do |fold|
        matches = @interpolations.select do |item|
          item.open == fold.open && item.close == fold.close && item.expression.same?(fold.expression)
        end
        raise ArgumentError.new("fold association differs") unless matches.size == 1
      end
      @heredoc_groups.each do |group|
        unless @graph.has_key?(group.placeholder.object_id) &&
               same_nodes?(group.placeholder.expressions, group.results)
          raise ArgumentError.new("heredoc result association differs")
        end
        opener = relationship_token!(group.opener, "DELIMITER_START")
        closer = relationship_token!(group.close, "DELIMITER_END")
        body = @journal.entry!(group.body)
        unless opener.delimiter.try(&.kind) == "HEREDOC" && opener.input_end <= body.input_start &&
               body.input_start <= closer.input_start && closer.input_end > closer.input_start
          raise ArgumentError.new("heredoc group boundaries differ")
        end
        group.results.each_with_index do |result, index|
          observations = @literal_owners.select { |item| item.owner.same?(result) && item.field == "value" && item.index == 0 }
          next if observations.empty?
          raise ArgumentError.new("heredoc result association differs") unless observations.size == 1
          observation = observations[0]
          parts = observation.productions
          next unless parts && parts.any? { |part| part.production.heredoc? }
          unless observation.heredoc_result_index == index && parts.size == 1 &&
                 parts[0].start_offset == opener.input_start && parts[0].end_offset == closer.input_end
            raise ArgumentError.new("heredoc result association differs")
          end
        end
      end
      @percent_groups.each do |group|
        unless @graph.has_key?(group.owner.object_id) && same_nodes?(group.owner.elements, group.elements)
          raise ArgumentError.new("percent array association differs")
        end
        opener = @journal.entry!(group.opener)
        unless {"STRING_ARRAY_START", "SYMBOL_ARRAY_START"}.includes?(opener.token_kind)
          raise ArgumentError.new("percent array opener differs")
        end
        relationship_token!(group.opener, opener.token_kind)
        closer = relationship_token!(group.close, "STRING_ARRAY_END")
        raise ArgumentError.new("percent array boundaries differ") unless opener.input_end <= closer.input_start
        previous = opener.input_end
        group.elements.each do |element|
          associations = @percent_elements.select { |item| item.owner.same?(element) }
          raise ArgumentError.new("percent array element association differs") unless associations.size == 1
          association = associations[0]
          first = @journal.entry!(association.first)
          ending = @journal.entry!(association.after)
          unless {"STRING", "INTERPOLATION_START"}.includes?(first.token_kind) &&
                 {"SPACE", "STRING_ARRAY_END"}.includes?(ending.token_kind) &&
                 first.lexical_mode == @mode && ending.lexical_mode == @mode &&
                 first.input_start >= previous && ending.input_start > first.input_start &&
                 ending.input_start <= closer.input_start
            raise ArgumentError.new("percent array element association differs")
          end
          relationship_token!(association.first, first.token_kind)
          relationship_token!(association.after, ending.token_kind)
          array_gap!(previous, first.input_start)
          observations = @literal_owners.select { |item| item.owner.same?(element) && item.field == "value" && item.index == 0 }
          raise ArgumentError.new("percent array element association differs") if observations.size > 1
          if observation = observations.first?
            if observation.productions.try { |parts| parts.any? { |part| part.production.percent_string_element? || part.production.percent_symbol_element? } }
              unless observation.ranges == [{first.input_start, ending.input_start}]
                raise ArgumentError.new("percent array element association differs")
              end
            end
          end
          previous = ending.input_start
        end
        array_gap!(previous, closer.input_start)
      end
      @payloads.each do |item|
        unless @graph.has_key?(item.owner.object_id) && @graph.has_key?(item.payload.object_id)
          raise ArgumentError.new("literal payload owner differs")
        end
        actual = case owner = item.owner
                 when RegexLiteral then owner.value
                 when Call
                   raise ArgumentError.new("literal payload owner differs") unless owner.name == "`"
                   owner.args.first? || raise ArgumentError.new("literal payload owner differs")
                 else
                   raise ArgumentError.new("literal payload owner differs")
                 end
        raise ArgumentError.new("literal payload owner differs") unless actual.same?(item.payload)
        opener = relationship_token!(item.opener, "DELIMITER_START")
        closer = relationship_token!(item.close, "DELIMITER_END")
        raise ArgumentError.new("literal payload bounds differ") unless opener.input_start < closer.input_end
      end
      verify_regex_options!
    end

    private def verify_wrapper!(wrapper : DiagnosticInterpolationWrapperObservation) : Nil
      unless @graph.has_key?(wrapper.owner.object_id) && same_nodes?(wrapper.owner.expressions, wrapper.expressions)
        raise ArgumentError.new("interpolation wrapper differs")
      end
      raise ArgumentError.new("interpolation wrapper lacks delimiters") if wrapper.delimiters.empty?
      pieces = @wrapper_pieces.select { |piece| piece.owner.same?(wrapper.owner) }.sort_by(&.index)
      unless pieces.size == wrapper.expressions.size
        raise ArgumentError.new("interpolation piece count differs")
      end
      if @journal.entry!(wrapper.delimiters.first[0]).token_kind == "STRING_ARRAY_START"
        verify_percent_wrapper!(wrapper, pieces)
        return
      end
      piece_index = 0
      previous_end : Int32? = nil
      wrapper.delimiters.each do |opening_ref, closing_ref|
        opening = relationship_token!(opening_ref, "DELIMITER_START")
        closing = relationship_token!(closing_ref, "DELIMITER_END")
        state = opening.delimiter || raise ArgumentError.new("interpolation delimiter state differs")
        raise ArgumentError.new("interpolation delimiter state differs") unless {"STRING", "REGEX", "COMMAND"}.includes?(state.kind)
        close_state = closing.delimiter
        unless close_state && close_state.kind == state.kind && close_state.nest == state.nest &&
               close_state.end_delimiter == state.end_delimiter && close_state.allow_escapes == state.allow_escapes
          raise ArgumentError.new("interpolation delimiter state differs")
        end
        if prior = previous_end
          continuation_gap!(prior, opening.input_start)
        end
        cursor = opening.input_end
        while cursor < closing.input_start
          token = @journal.entry_at!(cursor, @mode)
          unless token.input_end > cursor && token.input_end <= closing.input_start
            raise ArgumentError.new("interpolation span is not tiled")
          end
          token_state = token.delimiter
          unless token_state && token_state.kind == state.kind && token_state.nest == state.nest &&
                 token_state.end_delimiter == state.end_delimiter && token_state.allow_escapes == state.allow_escapes
            raise ArgumentError.new("interpolation delimiter state differs")
          end
          if token.token_kind == "STRING_CONTINUATION"
            cursor = token.input_end
            next
          end
          piece = pieces[piece_index]? || raise ArgumentError.new("interpolation piece count differs")
          cursor = verify_wrapper_piece!(wrapper, piece, piece_index, token)
          piece_index += 1
        end
        raise ArgumentError.new("interpolation span is not tiled") unless cursor == closing.input_start
        previous_end = closing.input_end
      end
      raise ArgumentError.new("interpolation piece count differs") unless piece_index == pieces.size
    end

    private def verify_percent_wrapper!(wrapper : DiagnosticInterpolationWrapperObservation,
                                        pieces : Array(DiagnosticInterpolationPieceObservation)) : Nil
      raise ArgumentError.new("percent interpolation delimiters differ") unless wrapper.delimiters.size == 1
      group = @percent_groups.select { |item| item.elements.any?(&.same?(wrapper.owner)) }
      bounds = @percent_elements.select { |item| item.owner.same?(wrapper.owner) }
      unless group.size == 1 && bounds.size == 1 &&
             wrapper.delimiters[0] == {group[0].opener, group[0].close}
        raise ArgumentError.new("percent interpolation delimiters differ")
      end
      opening = relationship_token!(group[0].opener, "STRING_ARRAY_START")
      closing = relationship_token!(group[0].close, "STRING_ARRAY_END")
      first = @journal.entry!(bounds[0].first)
      ending = @journal.entry!(bounds[0].after)
      state = opening.delimiter || raise ArgumentError.new("interpolation delimiter state differs")
      unless state.kind == "STRING_ARRAY" && first.input_start >= opening.input_end &&
             ending.input_start <= closing.input_start
        raise ArgumentError.new("percent interpolation delimiters differ")
      end
      cursor = first.input_start
      index = 0
      while cursor < ending.input_start
        token = @journal.entry_at!(cursor, @mode)
        token_state = token.delimiter
        unless token.input_end > cursor && token.input_end <= ending.input_start &&
               token_state && token_state.kind == state.kind && token_state.nest == state.nest &&
               token_state.end_delimiter == state.end_delimiter && token_state.allow_escapes == state.allow_escapes
          raise ArgumentError.new("interpolation delimiter state differs")
        end
        if token.token_kind == "STRING_CONTINUATION"
          cursor = token.input_end
          next
        end
        piece = pieces[index]? || raise ArgumentError.new("interpolation piece count differs")
        cursor = verify_wrapper_piece!(wrapper, piece, index, token)
        index += 1
      end
      unless cursor == ending.input_start && index == pieces.size
        raise ArgumentError.new("interpolation piece count differs")
      end
    end

    private def verify_wrapper_piece!(wrapper : DiagnosticInterpolationWrapperObservation,
                                      piece : DiagnosticInterpolationPieceObservation,
                                      index : Int32, token : DiagnosticRenderedToken) : Int32
      unless piece.index == index && piece.expression.same?(wrapper.expressions[index]) &&
             @journal.entry!(piece.first) == token
        raise ArgumentError.new("interpolation piece association differs")
      end
      case token.token_kind
      when "STRING"
        unless @journal.entry!(piece.last) == token && piece.expression.is_a?(StringLiteral)
          raise ArgumentError.new("interpolation piece association differs")
        end
        observations = @literal_owners.select do |item|
          item.owner.same?(piece.expression) && item.field == "value" && item.index == 0
        end
        unless observations.size == 1 && observations[0].ranges == [{token.input_start, token.input_end}]
          raise ArgumentError.new("interpolation piece association differs")
        end
        token.input_end
      when "INTERPOLATION_START"
        ending = relationship_token!(piece.last, "}")
        matches = @interpolations.select { |item| @journal.entry!(item.open) == token && @journal.entry!(item.close) == ending }
        raise ArgumentError.new("interpolation piece association differs") unless matches.size == 1
        source = matches[0].expression
        transferred = @transfers.any? { |item| item.source.same?(source) && item.target.same?(piece.expression) }
        unless piece.expression.same?(source) || transferred
          raise ArgumentError.new("interpolation piece association differs")
        end
        ending.input_end
      else
        raise ArgumentError.new("interpolation span is not tiled")
      end
    end

    private def continuation_gap!(start : Int32, finish : Int32) : Nil
      cursor = start
      first = true
      while cursor < finish
        token = @journal.entry_at!(cursor, @mode)
        unless token.token_kind == "SPACE" && token.input_end > cursor && token.input_end <= finish &&
               (!first || token.passed_backslash_newline)
          raise ArgumentError.new("continuation lacks a backslash-newline")
        end
        first = false
        cursor = token.input_end
      end
      raise ArgumentError.new("continuation lacks a backslash-newline") if first
    end

    private def verify_interpolation_prefix!(item : DiagnosticInterpolationObservation,
                                             opener : DiagnosticRenderedToken,
                                             first : DiagnosticRenderedToken) : Nil
      splats = @percent_elements.select do |element|
        element.first == item.open && element.owner.is_a?(Splat) &&
          @percent_groups.any? { |group| group.elements.any?(&.same?(element.owner)) }
      end
      raise ArgumentError.new("interpolation association differs") if splats.size > 1
      unless splats.empty?
        value = splats[0].owner.as(Splat).exp
        transferred = @transfers.any? { |transfer| transfer.source.same?(item.expression) && transfer.target.same?(value) }
        unless value.same?(item.expression) || transferred
          raise ArgumentError.new("interpolation association differs")
        end
      end
      cursor = opener.input_end
      star = false
      while cursor < first.input_start
        token = @journal.entry_at!(cursor, @mode)
        raise ArgumentError.new("interpolation association differs") unless token.input_end > cursor && token.input_end <= first.input_start
        if token.token_kind == "*"
          raise ArgumentError.new("interpolation association differs") if star || splats.empty?
          star = true
        elsif !{"SPACE", "NEWLINE", "SKIPPED_COMMENT", "SKIPPED_DOC_COMMENT", "SKIPPED_LOC_PRAGMA"}.includes?(token.token_kind)
          raise ArgumentError.new("interpolation association differs")
        end
        cursor = token.input_end
      end
      raise ArgumentError.new("interpolation association differs") unless star == !splats.empty?
    end

    private def array_gap!(start : Int32, finish : Int32) : Nil
      cursor = start
      while cursor < finish
        token = @journal.entry_at!(cursor, @mode)
        unless token.token_kind == "SPACE" && token.input_end > cursor && token.input_end <= finish
          raise ArgumentError.new("percent array separator differs")
        end
        cursor = token.input_end
      end
    end

    private def same_nodes?(actual : Indexable(ASTNode), expected : Indexable(ASTNode)) : Bool
      return false unless actual.size == expected.size
      actual.each_with_index { |node, index| return false unless node.same?(expected[index]) }
      true
    end

    private def same_literal_production?(left : DiagnosticLiteralProductionSegment,
                                         right : DiagnosticLiteralProductionSegment) : Bool
      left.production == right.production && left.start_offset == right.start_offset &&
        left.end_offset == right.end_offset && left.raw_base64 == right.raw_base64 &&
        left.delimiter_kind == right.delimiter_kind && left.nest == right.nest &&
        left.end_delimiter == right.end_delimiter && left.allow_escapes == right.allow_escapes &&
        left.witnesses == right.witnesses
    end

    def verify_regex_options! : Nil
      seen = Set(UInt64).new
      @regex_options.each do |observation|
        node = observation.owner
        raise ArgumentError.new("duplicate regex options association") unless seen.add?(node.object_id)
        raise ArgumentError.new("regex owner is not reachable") unless @graph.has_key?(node.object_id)
        opener = relationship_token!(observation.opener, "DELIMITER_START")
        closer = relationship_token!(observation.close, "DELIMITER_END")
        unless opener.delimiter.try(&.kind) == "REGEX" && opener.input_start < closer.input_start
          raise ArgumentError.new("regex delimiter association differs")
        end
        payloads = @payloads.select do |item|
          item.owner.same?(node) && item.payload.same?(node.value) &&
            item.opener == observation.opener && item.close == observation.close
        end
        raise ArgumentError.new("regex payload association differs") unless payloads.size == 1
        raise ArgumentError.new("regex modifier association differs") if observation.modifiers.size > 1
        cursor = closer.input_end
        options = RegexOptions::None
        if reference = observation.modifiers.first?
          modifier = relationship_token!(reference, "REGEX_OPTIONS")
          unless modifier.input_start == cursor && modifier.input_end > cursor
            raise ArgumentError.new("regex modifier association differs")
          end
          modifier.token_text.each_byte do |byte|
            case byte
            when 'i'.ord then options |= RegexOptions::IGNORE_CASE
            when 'm'.ord then options |= RegexOptions::MULTILINE
            when 'x'.ord then options |= RegexOptions::EXTENDED
            else              raise ArgumentError.new("invalid regex option")
            end
          end
          cursor = modifier.input_end
        end
        after = @journal.entry!(observation.after)
        unless after.lexical_mode == @mode && after.input_start >= cursor
          raise ArgumentError.new("regex return token differs")
        end
        @journal.literal_trivia!(cursor, after.input_start, @mode, true)
        raise ArgumentError.new("regex options differ") unless node.options == options
      end
      @graph.each_value do |snapshot|
        if snapshot.owner.is_a?(RegexLiteral) && !seen.includes?(snapshot.owner.object_id)
          raise ArgumentError.new("regex options association missing")
        end
      end
    end

    private def relationship_token!(reference : DiagnosticReplayTokenRef, kind : String) : DiagnosticRenderedToken
      token = @journal.entry!(reference)
      @journal.literal_entry!(token.input_start, token.input_end, kind, @mode)
    end

    private def copy_owner(item : DiagnosticLiteralOwnerObservation) : DiagnosticLiteralOwnerObservation
      productions = item.productions.try do |items|
        items.map do |part|
          DiagnosticLiteralProductionSegment.new(part.production, part.start_offset, part.end_offset,
            String.new(part.raw_base64.to_slice), part.delimiter_kind.try { |s| String.new(s.to_slice) },
            part.nest.try { |s| String.new(s.to_slice) }, part.end_delimiter.try { |s| String.new(s.to_slice) },
            part.allow_escapes, part.witnesses)
        end
      end
      DiagnosticLiteralOwnerObservation.new(item.owner, String.new(item.field.to_slice), item.index,
        item.ranges.dup, productions, item.heredoc_result_index)
    end

    private def freeze_graph!(node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("literal replay graph exceeds depth limit") if depth > 128
      id = node.object_id
      raise ArgumentError.new("cyclic literal replay graph") if @active.includes?(id)
      return if @graph.has_key?(id)
      remaining = DiagnosticOrigin::MAX_UNFOLDED_BYTES - 128_u64
      @active.add(id)
      begin
        DiagnosticAstFieldSchema.validate_node_fields(node)
        edges = [] of Edge
        DiagnosticDirectChildFields.each(node) do |field, index, key, child|
          charge = 64_u64 + field.bytesize.to_u64 + (key.try(&.bytesize) || 0).to_u64
          raise ArgumentError.new("literal replay node exceeds size limit") if charge > remaining
          remaining -= charge
          edges << Edge.new(String.new(field.to_slice), index, key.try { |value| String.new(value.to_slice) }, child)
        end
        @graph[id] = NodeEdges.new(node, edges)
        @coordinates[id] = @path.to_json
        edges.each do |edge|
          @path << {edge.field, edge.index, edge.key.try { |value| Base64.strict_encode(value) }}
          begin
            freeze_graph!(edge.child, depth + 1)
          ensure
            @path.pop
          end
        end
      ensure
        @active.delete(id)
      end
    end
  end

  # Reconstructs literal values from the replay journal. This does not by
  # itself establish the association between a literal and its AST owner.
  class DiagnosticLiteralReplay
    def initialize(@input : AcceptedCaptureInput, @journal : DiagnosticReplayJournal,
                   @folds : Array(DiagnosticFoldedStringObservation),
                   @interpolations : Array(DiagnosticInterpolationObservation),
                   @literal_observations : Array(DiagnosticLiteralOwnerObservation))
      @source = @input.input
    end

    # Structural expectations come from the parser's private observation,
    # never from the metadata being checked.
    def derive!(ranges : Indexable({Int32, Int32}), productions : Indexable(DiagnosticLiteralProductionSegment),
                depth : Int32 = 0, heredoc_value : String? = nil) : String
      raise ArgumentError.new("literal fold exceeds depth limit") if depth > 128
      raise ArgumentError.new("literal production evidence missing") if productions.empty?
      raise ArgumentError.new("literal constituent and production counts differ") unless ranges.size == productions.size
      output = IO::Memory.new
      previous_end : Int32? = nil
      ranges.each_with_index do |range, index|
        start_offset, end_offset = range
        unless start_offset >= 0 && end_offset > start_offset && end_offset <= @source.bytesize
          raise ArgumentError.new("literal constituent span invalid")
        end
        raw = @source.byte_slice(start_offset, end_offset - start_offset)
        segment = DiagnosticLiteralSegment.new(start_offset, end_offset, Base64.strict_encode(raw.to_slice))
        production = productions[index]
        unless @input.matches_encoded_span?(production.start_offset, production.end_offset, production.raw_base64)
          raise ArgumentError.new("literal production input bytes mismatch")
        end
        if production.production.percent_symbol_element? || production.production.percent_string_element?
          unless start_offset >= production.start_offset && end_offset <= production.end_offset
            raise ArgumentError.new("percent element lies outside production")
          end
        elsif start_offset != production.start_offset || end_offset != production.end_offset
          raise ArgumentError.new("literal constituent and production span mismatch")
        end
        case production.production
        when .symbol_token?, .char_token?, .magic_file?, .magic_dir?, .string_piece?
          raise ArgumentError.new("invalid atomic literal continuation") if previous_end
          output << @journal.literal_atom!(production, @input.lexical_mode)
        when .delimiter?
          output << delimiter_value!(production, previous_end, depth)
        when .percent_symbol_element?, .percent_string_element?
          raise ArgumentError.new("invalid percent literal continuation") if previous_end
          output << percent_value!(segment, production, depth)
        when .heredoc?
          raise ArgumentError.new("heredoc literal outside its heredoc") if previous_end
          output << (heredoc_value || raise ArgumentError.new("heredoc literal outside its heredoc"))
        else
          raise ArgumentError.new("literal production requires complete journal reconstruction")
        end
        previous_end = production.end_offset
      end
      output.to_s
    end

    # Low-level check for tests. Registry authorization uses derive! with the
    # parser-owned structural association, then compares the claimed fields.
    def value!(literal : DiagnosticParsedLiteral, productions : Indexable(DiagnosticLiteralProductionSegment),
               depth : Int32 = 0, heredoc_value : String? = nil) : String
      segments = literal.segments
      value = derive!(segments.map { |segment| {segment.start_offset, segment.end_offset} }, productions, depth, heredoc_value)
      verify_claim!(literal, value)
      value
    end

    def verify_claim!(literal : DiagnosticParsedLiteral, value : String) : Nil
      unless literal.input_sha256 == @input.input_sha256 && literal.input_bytesize == @input.input_bytesize &&
             literal.lexical_mode == @input.lexical_mode
        raise ArgumentError.new("literal input identity mismatch")
      end
      raise ArgumentError.new("literal expansion requires independent expansion authority") if literal.expansion
      literal.each_segment do |segment|
        unless @input.matches_encoded_span?(segment.start_offset, segment.end_offset, segment.raw_base64)
          raise ArgumentError.new("literal constituent input bytes mismatch")
        end
      end
      unless literal.decoded_bytesize == value.bytesize && literal.decoded_base64 == Base64.strict_encode(value.to_slice)
        raise ArgumentError.new("literal decoded value differs from scanned tokens")
      end
    end

    # A heredoc can yield several string nodes sharing one production. Derive
    # all of them together, so a repeated value cannot select a different part.
    def heredoc_values!(parent : StringInterpolation, production : DiagnosticLiteralProductionSegment) : Hash(UInt64, String)
      raise ArgumentError.new("invalid heredoc production") unless production.production.heredoc?
      witnesses = production.witnesses
      opener = witnesses.first? || raise ArgumentError.new("heredoc opener is not a scanned token")
      closer = witnesses.last? || raise ArgumentError.new("heredoc closer differs")
      unless opener.kind.opener? && opener.start_offset == production.start_offset &&
             closer.kind.closing_delimiter? && closer.end_offset == production.end_offset
        raise ArgumentError.new("heredoc closer differs")
      end
      opening_token = @journal.literal_entry!(opener.start_offset, opener.end_offset, "DELIMITER_START", @input.lexical_mode)
      closing_token = @journal.literal_entry!(closer.start_offset, closer.end_offset, "DELIMITER_END", @input.lexical_mode)
      state!(opening_token, production)
      state!(closing_token, production)
      closing_state = closing_token.delimiter.not_nil!
      raise ArgumentError.new("heredoc closer differs") unless closing_state.heredoc_indent == parent.heredoc_indent
      pieces = [] of HeredocIndent::Piece(Int32)
      expressions = [] of ASTNode
      index = 1
      marker = 0
      cursor = witnesses[index]?.try(&.start_offset) || closing_token.input_start
      @journal.ends_at(cursor).each do |entry|
        next unless {"STRING", "STRING_CONTINUATION", "INTERPOLATION_START"}.includes?(entry.token_kind)
        state = entry.delimiter
        if state && state.kind == production.delimiter_kind && state.nest == production.nest &&
           state.end_delimiter == production.end_delimiter && state.allow_escapes == production.allow_escapes
          raise ArgumentError.new("unwitnessed heredoc body token")
        end
      end
      while cursor < closing_token.input_start
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        unless token.input_end > cursor && token.input_end <= closing_token.input_start
          raise ArgumentError.new("unwitnessed heredoc body token")
        end
        state!(token, production)
        case token.token_kind
        when "STRING"
          witness = witnesses[index]? || raise ArgumentError.new("unwitnessed heredoc body token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::StringPiece)
          raise ArgumentError.new("literal string token has an invalid escape") if token.invalid_escape
          line = token.line || raise ArgumentError.new("heredoc token lacks line")
          pieces << HeredocIndent::Piece(Int32).new(String.new(token_value!(token)), line)
          index += 1
        when "STRING_CONTINUATION"
        when "INTERPOLATION_START"
          witness = witnesses[index]? || raise ArgumentError.new("unwitnessed heredoc body token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::InterpolationStart)
          ending = witnesses[index + 1]? || raise ArgumentError.new("unwitnessed heredoc body token")
          raise ArgumentError.new("unwitnessed heredoc body token") unless ending.kind.interpolation_end?
          closing_expression = @journal.literal_entry!(ending.start_offset, ending.end_offset, "}", @input.lexical_mode)
          associations = @interpolations.select do |observation|
            @journal.entry!(observation.open) == token && @journal.entry!(observation.close) == closing_expression
          end
          raise ArgumentError.new("heredoc interpolation association differs") unless associations.size == 1
          expressions << associations[0].expression
          first_expression = @journal.entry!(associations[0].expression_first)
          unless first_expression.lexical_mode == @input.lexical_mode &&
                 first_expression.input_start >= token.input_end && first_expression.input_end <= ending.start_offset
            raise ArgumentError.new("heredoc interpolation association differs")
          end
          @journal.literal_trivia!(token.input_end, first_expression.input_start, @input.lexical_mode, true)
          line = first_expression.line || raise ArgumentError.new("heredoc expression lacks line")
          pieces << HeredocIndent::Piece(Int32).new(marker, line)
          marker += 1
          cursor = ending.end_offset
          index += 2
          next
        else
          raise ArgumentError.new("unwitnessed heredoc body token")
        end
        cursor = token.input_end
      end
      unless cursor == closing_token.input_start && index == witnesses.size - 1
        raise ArgumentError.new("unwitnessed heredoc body token")
      end
      values = begin
                 HeredocIndent.remove(pieces, parent.heredoc_indent)
               rescue HeredocIndent::Error
                 raise ArgumentError.new("heredoc indentation invalid")
               end
      derived = {} of UInt64 => String
      if marker == 0
        child = parent.expressions.first?
        unless parent.expressions.size == 1 && child.is_a?(StringLiteral)
          raise ArgumentError.new("heredoc value differs from replayed indentation")
        end
        value = values.join { |part| part.as(String) }
        derived[child.object_id] = value
      else
        raise ArgumentError.new("heredoc value differs from replayed indentation") unless parent.expressions.size == values.size
        values.each_with_index do |part, i|
          child = parent.expressions[i]
          if part.is_a?(String)
            raise ArgumentError.new("heredoc value differs from replayed indentation") unless child.is_a?(StringLiteral)
            derived[child.object_id] = part
          else
            unless child.same?(expressions[part])
              raise ArgumentError.new("heredoc interpolation association differs")
            end
          end
        end
      end
      derived
    end

    private def percent_value!(segment : DiagnosticLiteralSegment, production : DiagnosticLiteralProductionSegment,
                               depth : Int32) : String
      witnesses = production.witnesses
      opener = witnesses.first? || raise ArgumentError.new("literal witness is not a scanned token")
      closer = witnesses.last? || raise ArgumentError.new("literal witness is not a scanned token")
      unless opener.kind.opener? && opener.start_offset == production.start_offset &&
             closer.kind.closing_delimiter? && closer.end_offset == production.end_offset
        raise ArgumentError.new("literal witness is not a scanned token")
      end
      opener_kind = production.production.percent_symbol_element? ? "SYMBOL_ARRAY_START" : "STRING_ARRAY_START"
      opening_token = @journal.literal_entry!(opener.start_offset, opener.end_offset, opener_kind, @input.lexical_mode)
      closing_token = @journal.literal_entry!(closer.start_offset, closer.end_offset, "STRING_ARRAY_END", @input.lexical_mode)
      state!(opening_token, production)
      state!(closing_token, production)
      unless segment.start_offset >= opening_token.input_end && segment.end_offset <= closing_token.input_start
        raise ArgumentError.new("percent element lies outside production")
      end
      preceding = @journal.ends_at(segment.start_offset).select do |token|
        token.input_end == segment.start_offset && token.lexical_mode == @input.lexical_mode &&
          (token == opening_token || token.token_kind == "SPACE")
      end.uniq
      following = @journal.entry_at!(segment.end_offset, @input.lexical_mode)
      unless preceding.size == 1 && (following == closing_token || following.token_kind == "SPACE")
        raise ArgumentError.new("percent element is not delimited by separators")
      end
      output = IO::Memory.new
      cursor = segment.start_offset
      index = 1
      while cursor < segment.end_offset
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        unless token.input_end > cursor && token.input_end <= segment.end_offset
          raise ArgumentError.new("literal span is not tiled by scanned tokens")
        end
        state!(token, production)
        case token.token_kind
        when "STRING"
          witness = witnesses[index]? || raise ArgumentError.new("unwitnessed scanned string token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::StringPiece)
          raise ArgumentError.new("literal string token has an invalid escape") if token.invalid_escape
          output.write(token_value!(token))
          index += 1
        when "STRING_CONTINUATION"
        when "INTERPOLATION_START"
          witness = witnesses[index]? || raise ArgumentError.new("literal witness is not a scanned token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::InterpolationStart)
          ending = witnesses[index + 1]? || raise ArgumentError.new("literal witness is not a scanned token")
          raise ArgumentError.new("literal witness is not a scanned token") unless ending.kind.interpolation_end?
          output << folded_value!(token, ending, depth + 1)
          cursor = ending.end_offset
          index += 2
          next
        else
          raise ArgumentError.new("literal span is not tiled by scanned tokens")
        end
        cursor = token.input_end
      end
      raise ArgumentError.new("unwitnessed scanned string token") unless index == witnesses.size - 1
      output.to_s
    end

    private def delimiter_value!(production : DiagnosticLiteralProductionSegment, previous_end : Int32?,
                                 depth : Int32) : String
      witnesses = production.witnesses
      index = 0
      if previous_end
        witness = witnesses[index]? || raise ArgumentError.new("continuation lacks a backslash-newline")
        unless witness.kind.continuation? && witness.start_offset == previous_end && witness.end_offset == production.start_offset
          raise ArgumentError.new("continuation lacks a backslash-newline")
        end
        continuation!(witness.start_offset, witness.end_offset)
        index += 1
      end
      opener = witnesses[index]? || raise ArgumentError.new("literal witness is not a scanned token")
      unless opener.kind.opener? && opener.start_offset == production.start_offset
        raise ArgumentError.new("literal witness is not a scanned token")
      end
      entry = @journal.literal_entry!(opener.start_offset, opener.end_offset, "DELIMITER_START", @input.lexical_mode)
      state!(entry, production)
      cursor = entry.input_end
      index += 1
      output = IO::Memory.new
      while cursor < production.end_offset
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        raise ArgumentError.new("literal span is not tiled by scanned tokens") unless token.input_end > cursor && token.input_end <= production.end_offset
        state!(token, production)
        case token.token_kind
        when "STRING"
          witness = witnesses[index]? || raise ArgumentError.new("unwitnessed scanned string token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::StringPiece)
          raise ArgumentError.new("literal string token has an invalid escape") if token.invalid_escape
          output.write(token_value!(token))
          index += 1
        when "STRING_CONTINUATION"
          # Continuations contribute no decoded bytes.
        when "INTERPOLATION_START"
          witness = witnesses[index]? || raise ArgumentError.new("literal witness is not a scanned token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::InterpolationStart)
          closing = witnesses[index + 1]? || raise ArgumentError.new("literal witness is not a scanned token")
          raise ArgumentError.new("literal witness is not a scanned token") unless closing.kind.interpolation_end?
          output << folded_value!(token, closing, depth + 1)
          cursor = closing.end_offset
          index += 2
          next
        when "DELIMITER_END"
          witness = witnesses[index]? || raise ArgumentError.new("literal witness is not a scanned token")
          witness!(witness, token, DiagnosticLiteralWitnessKind::ClosingDelimiter)
          unless token.input_end == production.end_offset && index + 1 == witnesses.size
            raise ArgumentError.new("literal span is not tiled by scanned tokens")
          end
          return output.to_s
        else
          raise ArgumentError.new("literal span is not tiled by scanned tokens")
        end
        cursor = token.input_end
      end
      raise ArgumentError.new("literal span is not tiled by scanned tokens")
    end

    private def folded_value!(opening : DiagnosticRenderedToken, closing : DiagnosticLiteralWitness,
                              depth : Int32) : String
      raise ArgumentError.new("literal fold exceeds depth limit") if depth > 128
      closer = @journal.literal_entry!(closing.start_offset, closing.end_offset, "}", @input.lexical_mode)
      matches = @folds.select do |fold|
        @journal.entry!(fold.open) == opening && @journal.entry!(fold.close) == closer
      end
      raise ArgumentError.new("folded interpolation is not a literal") unless matches.size == 1
      expression = matches[0].expression
      observations = @literal_observations.select do |item|
        item.owner.same?(expression) && item.field == "value" && item.index == 0
      end
      raise ArgumentError.new("folded literal owner association differs") unless observations.size == 1
      association = observations[0]
      expected = association.productions || raise ArgumentError.new("folded literal owner association differs")
      raise ArgumentError.new("folded interpolation is not a literal") if association.ranges.empty?
      first = association.ranges.first[0]
      last = association.ranges.last[1]
      unless opening.input_end <= first && last <= closer.input_start
        raise ArgumentError.new("folded interpolation is not a literal")
      end
      @journal.literal_trivia!(opening.input_end, first, @input.lexical_mode, true)
      @journal.literal_trivia!(last, closer.input_start, @input.lexical_mode, true)
      value = derive!(association.ranges, expected, depth)
      literal = expression.diagnostic_literal_names[{"value", 0}]? ||
                raise ArgumentError.new("folded interpolation is not a literal")
      productions = expression.diagnostic_literal_productions[{"value", 0}]? ||
                    raise ArgumentError.new("folded interpolation is not a literal")
      unless literal.segments.map { |segment| {segment.start_offset, segment.end_offset} } == association.ranges &&
             productions.size == expected.size && productions.zip(expected).all? { |pair| same_production?(pair[0], pair[1]) }
        raise ArgumentError.new("folded literal owner association differs")
      end
      verify_claim!(literal, value)
      raise ArgumentError.new("literal decoded value differs from scanned tokens") unless value == expression.value
      value
    end

    private def continuation!(start : Int32, finish : Int32) : Nil
      cursor = start
      first = true
      while cursor < finish
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        unless token.token_kind == "SPACE" && token.input_end > cursor && token.input_end <= finish &&
               (!first || token.passed_backslash_newline)
          raise ArgumentError.new("continuation lacks a backslash-newline")
        end
        first = false
        cursor = token.input_end
      end
      raise ArgumentError.new("continuation lacks a backslash-newline") if first
    end

    private def state!(token : DiagnosticRenderedToken, production : DiagnosticLiteralProductionSegment) : Nil
      state = token.delimiter
      unless state && state.kind == production.delimiter_kind && state.nest == production.nest &&
             state.end_delimiter == production.end_delimiter && state.allow_escapes == production.allow_escapes
        raise ArgumentError.new("literal delimiter state differs from scanned token")
      end
    end

    private def witness!(witness : DiagnosticLiteralWitness, token : DiagnosticRenderedToken,
                         kind : DiagnosticLiteralWitnessKind) : Nil
      unless witness.kind == kind && witness.start_offset == token.input_start && witness.end_offset == token.input_end
        raise ArgumentError.new("literal witness is not a scanned token")
      end
    end

    private def same_production?(left : DiagnosticLiteralProductionSegment,
                                 right : DiagnosticLiteralProductionSegment) : Bool
      left.production == right.production && left.start_offset == right.start_offset &&
        left.end_offset == right.end_offset && left.raw_base64 == right.raw_base64 &&
        left.delimiter_kind == right.delimiter_kind && left.nest == right.nest &&
        left.end_delimiter == right.end_delimiter && left.allow_escapes == right.allow_escapes &&
        left.witnesses == right.witnesses
    end

    private def token_value!(token : DiagnosticRenderedToken) : Bytes
      encoded = token.value_base64 || raise ArgumentError.new("literal scanned token lacks a value")
      DiagnosticRenderedToken.decode_value(encoded, DiagnosticRenderedToken.value_bound(token.token_kind, token.token_text))
    end
  end

  # Binds literal metadata to parser-owned observations before considering its
  # value. The observations bind the owner and occurrence, not decoded bytes.
  class DiagnosticLiteralOwnerBinding
    def initialize(@replay : DiagnosticLiteralReplay, observations : Array(DiagnosticLiteralOwnerObservation))
      @by_owner = {} of UInt64 => Hash({String, Int32}, DiagnosticLiteralOwnerObservation)
      observations.each do |item|
        keys = (@by_owner[item.owner.object_id] ||= {} of {String, Int32} => DiagnosticLiteralOwnerObservation)
        key = {item.field, item.index}
        raise ArgumentError.new("duplicate literal owner association") if keys.has_key?(key)
        keys[key] = item
      end
    end

    def verify!(root : ASTNode, scalar_verified : Set(UInt64),
                bundle : DiagnosticLiteralReplayAssociations) : Set(DiagnosticCaptureFieldRef)
      bundle.verify_graph!(root)
      bundle.verify_relationships!
      verified = Set(DiagnosticCaptureFieldRef).new
      heredocs = {} of UInt64 => String
      visit!(root, scalar_verified, bundle, verified, heredocs, Set(UInt64).new, Set(UInt64).new, 0)
      verified
    end

    private def visit!(node : ASTNode, scalar_verified : Set(UInt64), bundle : DiagnosticLiteralReplayAssociations,
                       verified : Set(DiagnosticCaptureFieldRef), heredocs : Hash(UInt64, String),
                       visited : Set(UInt64), active : Set(UInt64), depth : Int32) : Nil
      raise ArgumentError.new("literal binding exceeds depth limit") if depth > 128
      raise ArgumentError.new("cyclic literal owner graph") if active.includes?(node.object_id)
      return unless visited.add?(node.object_id)
      active.add(node.object_id)
      begin
        if node.is_a?(Require) || node.is_a?(Asm) || node.is_a?(AsmOperand)
          raise ArgumentError.new("scalar grammar binding missing") unless scalar_verified.includes?(node.object_id)
        end
        if node.is_a?(StringInterpolation)
          heredoc_values!(node).each do |id, value|
            raise ArgumentError.new("duplicate heredoc output owner") if heredocs.has_key?(id)
            heredocs[id] = value
          end
        end
        verify_node!(node, heredocs[node.object_id]?)
        node.each_diagnostic_literal_name do |key, _|
          verified.add(bundle.field_ref(node, key[0], key[1]))
        end
        DiagnosticDirectChildFields.each(node) do |_, _, _, child|
          visit!(child, scalar_verified, bundle, verified, heredocs, visited, active, depth + 1)
        end
      ensure
        active.delete(node.object_id)
      end
    end

    def verify_key!(node : ASTNode, field : String, index : Int32, expected : String,
                    heredoc_value : String? = nil) : Nil
      value, _, _ = derive_key!(node, field, index, heredoc_value)
      raise ArgumentError.new("literal decoded value differs from scanned tokens") unless value == expected
    end

    def derive_key!(node : ASTNode, field : String, index : Int32,
                    heredoc_value : String? = nil) : {String, Int32, Int32}
      observation = @by_owner[node.object_id]?.try(&.[{field, index}]?) ||
                    raise ArgumentError.new("literal owner association differs")
      raise ArgumentError.new("literal owner association differs") unless observation.owner.same?(node)
      expected_productions = observation.productions ||
                             raise ArgumentError.new("literal owner production missing")
      value = @replay.derive!(observation.ranges, expected_productions, heredoc_value: heredoc_value)
      literal = node.diagnostic_literal_names[{field, index}]? ||
                raise ArgumentError.new("literal owner observation missing")
      productions = node.diagnostic_literal_productions[{field, index}]? ||
                    raise ArgumentError.new("literal owner production missing")
      actual_ranges = literal.segments.map { |segment| {segment.start_offset, segment.end_offset} }
      unless actual_ranges == observation.ranges && productions.size == expected_productions.size
        raise ArgumentError.new("literal owner association differs")
      end
      productions.each_with_index do |production, i|
        unless same_production?(production, expected_productions[i])
          raise ArgumentError.new("literal owner association differs")
        end
      end
      @replay.verify_claim!(literal, value)
      {value, observation.ranges.first[0], observation.ranges.last[1]}
    end

    def heredoc_values!(parent : StringInterpolation) : Hash(UInt64, String)
      common : DiagnosticLiteralProductionSegment? = nil
      parent.expressions.each_with_index do |child, index|
        observation = @by_owner[child.object_id]?.try(&.[{"value", 0}]?)
        next unless observation
        productions = observation.productions
        next unless productions && productions.any? { |production| production.production.heredoc? }
        unless observation.owner.same?(child) && observation.heredoc_result_index == index &&
               productions.size == 1 && productions[0].production.heredoc?
          raise ArgumentError.new("heredoc literal outside its heredoc")
        end
        if prior = common
          raise ArgumentError.new("heredoc productions differ") unless same_production?(prior, productions[0])
        else
          common = productions[0]
        end
      end
      return {} of UInt64 => String unless common
      values = @replay.heredoc_values!(parent, common)
      values.each do |id, value|
        child = parent.expressions.find { |item| item.object_id == id } ||
                raise ArgumentError.new("heredoc literal outside its heredoc")
        observation = @by_owner[id]?.try(&.[{"value", 0}]?) ||
                      raise ArgumentError.new("heredoc literal outside its heredoc")
        expected = observation.productions
        unless expected && expected.size == 1 && same_production?(expected[0], common)
          raise ArgumentError.new("heredoc productions differ")
        end
        verify_key!(child, "value", 0, value, value)
      end
      values
    end

    def verify_node!(node : ASTNode, heredoc_value : String? = nil) : Nil
      names = node.diagnostic_literal_names
      productions = node.diagnostic_literal_productions
      unless node.diagnostic_literal_names_present? == node.diagnostic_literal_productions_present?
        raise ArgumentError.new("literal observations and productions differ in presence or count")
      end
      observed_keys = @by_owner[node.object_id]?.try(&.keys) || [] of {String, Int32}
      unless observed_keys.to_set == names.keys.to_set
        raise ArgumentError.new("literal owner association differs")
      end
      unless names.keys.to_set == productions.keys.to_set
        raise ArgumentError.new("literal observations and productions differ in presence or count")
      end
      if node.is_a?(StringLiteral) || node.is_a?(SymbolLiteral) || node.is_a?(CharLiteral)
        unless names.size == 1 && names.has_key?({"value", 0})
          raise ArgumentError.new("literal value lacks source or construction evidence")
        end
      end
      names.each_key do |key|
        field, index = key
        # Asm options have no string collection in the AST. Their expected
        # values must be supplied by the independent scalar grammar replay.
        next if node.is_a?(Asm) && field == "options"
        expected = DiagnosticLiteralInputChecks.owner_value(node, field, index)
        verify_key!(node, field, index, expected, heredoc_value)
      end
    end

    private def same_production?(left : DiagnosticLiteralProductionSegment,
                                 right : DiagnosticLiteralProductionSegment) : Bool
      left.production == right.production && left.start_offset == right.start_offset &&
        left.end_offset == right.end_offset && left.raw_base64 == right.raw_base64 &&
        left.delimiter_kind == right.delimiter_kind && left.nest == right.nest &&
        left.end_delimiter == right.end_delimiter && left.allow_escapes == right.allow_escapes &&
        left.witnesses == right.witnesses
    end
  end

  # Binds each NumberLiteral to one occurrence in the fresh replay. The value and
  # kind come from the lexer journal; the node is compared with them, never the
  # other way round. Literal, TypeArgument and Offset read NUMBER tokens,
  # Backreference reads GLOBAL_MATCH_DATA_INDEX, and Line reads __LINE__.
  class DiagnosticNumberLiteralBinding
    BACKREFERENCE = /\A\$[0-9]+\??\z/

    def self.from(input : AcceptedCaptureInput, bundle : DiagnosticLiteralReplayAssociations) : self
      new(input, bundle, bundle.numbers, bundle.signed_numbers)
    end

    def initialize(@input : AcceptedCaptureInput, @bundle : DiagnosticLiteralReplayAssociations,
                   @observations : Array(DiagnosticNumberObservation),
                   @signed : Array(DiagnosticSignedNumberObservation))
      @journal = @bundle.journal
    end

    def verify!(root : ASTNode) : Set(DiagnosticCaptureFieldRef)
      raise ArgumentError.new("literal replay input differs") unless @bundle.input_key == @input.capture_key
      @bundle.verify_graph!(root)
      fields = Set(DiagnosticCaptureFieldRef).new
      owners = Set(UInt64).new
      used = Set(Int32).new
      literal_used = Set(Int32).new
      @observations.each do |item|
        owner = item.owner
        raise ArgumentError.new("duplicate number literal association") unless owners.add?(owner.object_id)
        raise ArgumentError.new("number literal owner is not reachable") unless @bundle.frozen?(owner)
        token_kind = case item.role
                     when .backreference? then "GLOBAL_MATCH_DATA_INDEX"
                     when .line?          then "__LINE__"
                     else                      "NUMBER"
                     end
        entry = token!(item.token, token_kind)
        raise ArgumentError.new("number token consumed twice") unless used.add?(item.token.ordinal)
        literal_used << item.token.ordinal if item.role.literal?
        value, number_kind = case item.role
                             when .backreference?
                               backreference!(owner, entry, item.call)
                             when .line?
                               raise ArgumentError.new("number observation call differs") unless item.call.nil?
                               line!(entry)
                             else
                               raise ArgumentError.new("number observation call differs") unless item.call.nil?
                               number!(item.role, entry)
                             end
        raise ArgumentError.new("number literal value differs from scanned token") unless owner.value == value
        raise ArgumentError.new("number literal kind differs from scanned token") unless owner.kind.to_s == number_kind
        fields << @bundle.field_ref(owner, "value", 0)
        fields << @bundle.field_ref(owner, "kind", 0)
      end
      @signed.each do |item|
        call = item.call
        raise ArgumentError.new("signed number operator is not reachable") unless @bundle.frozen?(call)
        signed = token!(item.signed, "NUMBER")
        unsigned = token!(item.unsigned, "NUMBER")
        sign = signed.token_text.byte_slice(0, 1)
        raise ArgumentError.new("signed number operator differs") unless {"+", "-"}.includes?(sign) && call.name == sign
        unless item.unsigned.ordinal > item.signed.ordinal && unsigned.input_start == signed.input_start + 1 &&
               unsigned.input_end == signed.input_end && unsigned.token_text == signed.token_text.byte_slice(1) &&
               literal_used.includes?(item.unsigned.ordinal)
          raise ArgumentError.new("signed number operand differs")
        end
        raise ArgumentError.new("number token consumed twice") unless used.add?(item.signed.ordinal)
      end
      @journal.entries.each_with_index do |entry, ordinal|
        next unless {"NUMBER", "GLOBAL_MATCH_DATA_INDEX"}.includes?(entry.token_kind)
        raise ArgumentError.new("unbound number token") unless used.includes?(ordinal)
      end
      @bundle.each_frozen do |owner, _|
        next unless owner.is_a?(NumberLiteral)
        raise ArgumentError.new("number literal binding missing") unless owners.includes?(owner.object_id)
      end
      fields
    end

    private def token!(reference : DiagnosticReplayTokenRef, kind : String) : DiagnosticRenderedToken
      entry = @journal.entry!(reference)
      @journal.literal_entry!(entry.input_start, entry.input_end, kind, @input.lexical_mode)
    end

    private def backreference!(owner : NumberLiteral, entry : DiagnosticRenderedToken, call : Call?) : {String, String}
      call = call || raise ArgumentError.new("backreference call association missing")
      raw = entry.token_text
      raise ArgumentError.new("backreference token differs") unless raw.matches?(BACKREFERENCE)
      query = raw.ends_with?('?')
      digits = query ? raw.byte_slice(1, raw.bytesize - 2) : raw.byte_slice(1)
      index = digits.to_i32? || raise ArgumentError.new("backreference token differs")
      raise ArgumentError.new("backreference call differs") unless @bundle.frozen?(call)
      global = call.obj
      raise ArgumentError.new("backreference call differs") unless global.is_a?(Global) && global.name == "$~"
      raise ArgumentError.new("backreference call differs") unless call.args.size == 1 && call.args[0].same?(owner)
      named = call.named_args
      raise ArgumentError.new("backreference call differs") if (named && !named.empty?) || call.block || call.block_arg
      raise ArgumentError.new("backreference call differs") unless call.name == (query ? "[]?" : "[]")
      {index.to_s, "i32"}
    end

    private def line!(entry : DiagnosticRenderedToken) : {String, String}
      value = journal_value!(entry, "number token lacks a value")
      raise ArgumentError.new("line number value is not canonical") unless value.to_i32?.try(&.to_s) == value
      {value, "i32"}
    end

    private def number!(role : DiagnosticNumberRole, entry : DiagnosticRenderedToken) : {String, String}
      value = journal_value!(entry, "number token lacks a value")
      kind = entry.number_kind || raise ArgumentError.new("number token lacks a kind")
      raise ArgumentError.new("offset number kind differs") if role.offset? && kind != "i32"
      {value, kind}
    end

    private def journal_value!(entry : DiagnosticRenderedToken, message : String) : String
      encoded = entry.value_base64 || raise ArgumentError.new(message)
      String.new(DiagnosticRenderedToken.decode_value(encoded, DiagnosticRenderedToken.value_bound(entry.token_kind, entry.token_text)))
    end
  end

  # Binds each MacroLiteral to one MACRO_LITERAL occurrence. The value must equal
  # the occurrence's source bytes (less an escape's backslash) and the node. Order
  # is checked only among the MacroLiteral children of a frozen Expressions.
  class DiagnosticMacroLiteralBinding
    def self.from(input : AcceptedCaptureInput, bundle : DiagnosticLiteralReplayAssociations) : self
      new(input, bundle, bundle.macro_literals)
    end

    def initialize(@input : AcceptedCaptureInput, @bundle : DiagnosticLiteralReplayAssociations,
                   @observations : Array(DiagnosticMacroLiteralObservation))
      @journal = @bundle.journal
    end

    def verify!(root : ASTNode) : Set(DiagnosticCaptureFieldRef)
      raise ArgumentError.new("literal replay input differs") unless @bundle.input_key == @input.capture_key
      @bundle.verify_graph!(root)
      fields = Set(DiagnosticCaptureFieldRef).new
      owners = Set(UInt64).new
      used = Set(Int32).new
      ordinals = {} of UInt64 => Int32
      @observations.each do |item|
        owner = item.owner
        raise ArgumentError.new("duplicate macro literal association") unless owners.add?(owner.object_id)
        raise ArgumentError.new("macro literal owner is not reachable") unless @bundle.frozen?(owner)
        entry = token!(item.token)
        raise ArgumentError.new("macro literal token consumed twice") unless used.add?(item.token.ordinal)
        encoded = entry.value_base64 || raise ArgumentError.new("macro literal token lacks a value")
        value = String.new(DiagnosticRenderedToken.decode_value(encoded, DiagnosticRenderedToken.value_bound(entry.token_kind, entry.token_text)))
        raw = entry.token_text
        expected = (raw.starts_with?("\\{") || raw.starts_with?("\\%")) ? raw.byte_slice(1) : raw
        raise ArgumentError.new("macro literal value differs from its source bytes") unless value == expected
        raise ArgumentError.new("macro literal value differs from scanned token") unless owner.value == value
        fields << @bundle.field_ref(owner, "value", 0)
        ordinals[owner.object_id] = item.token.ordinal
      end
      @journal.entries.each_with_index do |entry, ordinal|
        next unless entry.token_kind == "MACRO_LITERAL"
        raise ArgumentError.new("unbound macro literal token") unless used.includes?(ordinal)
      end
      @bundle.each_frozen do |owner, _|
        next unless owner.is_a?(MacroLiteral)
        raise ArgumentError.new("macro literal binding missing") unless owners.includes?(owner.object_id)
      end
      @bundle.each_frozen do |owner, edges|
        next unless owner.is_a?(Expressions)
        last = -1
        edges.each do |edge|
          next unless edge.child.is_a?(MacroLiteral)
          ordinal = ordinals[edge.child.object_id]
          raise ArgumentError.new("macro literal order differs from scanned tokens") unless ordinal > last
          last = ordinal
        end
      end
      fields
    end

    private def token!(reference : DiagnosticReplayTokenRef) : DiagnosticRenderedToken
      entry = @journal.entry!(reference)
      @journal.literal_entry!(entry.input_start, entry.input_end, "MACRO_LITERAL", @input.lexical_mode)
    end
  end

  # Replays the scalar grammar from lexer observations. Owner associations
  # delimit parser invocations; they do not supply occurrence counts or values.
  class DiagnosticScalarGrammarReplay
    record AsmInterval, owner : UInt64, start : Int32, finish : Int32, ancestors : Set(UInt64)

    def initialize(@input : AcceptedCaptureInput, @journal : DiagnosticReplayJournal,
                   @owners : DiagnosticLiteralOwnerBinding, observations : Array(DiagnosticScalarGrammarObservation))
      @observations = {} of UInt64 => DiagnosticScalarGrammarObservation
      observations.each do |observation|
        id = observation.owner.object_id
        raise ArgumentError.new("duplicate scalar owner association") if @observations.has_key?(id)
        @observations[id] = observation
      end
      @verified = Set(UInt64).new
      @active = Set(UInt64).new
      @path = [] of ASTNode
      @intervals = [] of AsmInterval
    end

    def verify!(root : ASTNode) : Set(UInt64)
      visit!(root, 0)
      verify_intervals!
      unless @verified.size == @observations.size
        raise ArgumentError.new("orphan scalar owner association")
      end
      @verified
    end

    private def visit!(node : ASTNode, depth : Int32) : Nil
      raise ArgumentError.new("scalar grammar exceeds depth limit") if depth > 128
      raise ArgumentError.new("cyclic scalar grammar") unless @active.add?(node.object_id)
      @path << node
      begin
        case node
        when Require
          verify_require!(node)
        when Asm
          record_interval!(node)
          verify_asm!(node)
        when AsmOperand
          observation!(node, DiagnosticScalarGrammarKind::AsmOperand)
          raise ArgumentError.new("asm operand is not owned by an asm section") unless @verified.includes?(node.object_id)
        end
        DiagnosticDirectChildFields.each(node) { |_, _, _, child| visit!(child, depth + 1) }
      ensure
        @path.pop
        @active.delete(node.object_id)
      end
    end

    private def record_interval!(node : Asm) : Nil
      observation = observation!(node, DiagnosticScalarGrammarKind::Asm)
      first = @journal.entry!(observation.first)
      close = @journal.entry!(observation.close)
      raise ArgumentError.new("asm interval differs") unless close.input_end > first.input_start
      ancestor_nodes = @path[0...-1].select { |item| item.is_a?(Asm) }
      if parent = ancestor_nodes.last?
        parent_index = @path.index { |item| item.same?(parent) }.not_nil!
        operand_index = ((parent_index + 1)...(@path.size - 1)).find { |i| @path[i].is_a?(AsmOperand) }
        raise ArgumentError.new("nested asm is not in an operand") unless operand_index
        operand = @path[operand_index].as(AsmOperand)
        outer = parent.as(Asm)
        owned = (outer.outputs || [] of AsmOperand).any?(&.same?(operand)) ||
                (outer.inputs || [] of AsmOperand).any?(&.same?(operand))
        unless owned && @path[operand_index + 1].same?(operand.exp)
          raise ArgumentError.new("nested asm is not in an operand")
        end
      end
      @intervals << AsmInterval.new(node.object_id, first.input_start, close.input_end,
        ancestor_nodes.map(&.object_id).to_set)
    end

    private def verify_intervals! : Nil
      stack = [] of AsmInterval
      @intervals.sort_by { |item| {item.start, -item.finish} }.each do |item|
        while !stack.empty? && stack.last.finish <= item.start
          stack.pop
        end
        unless stack.empty?
          outer = stack.last
          unless item.start > outer.start && item.finish <= outer.finish && item.ancestors.includes?(outer.owner)
            raise ArgumentError.new("overlapping asm owner intervals")
          end
        end
        stack << item
      end
    end

    private def observation!(node : ASTNode, kind : DiagnosticScalarGrammarKind) : DiagnosticScalarGrammarObservation
      observation = @observations[node.object_id]? || raise ArgumentError.new("scalar owner association missing")
      unless observation.owner.same?(node) && observation.kind == kind
        raise ArgumentError.new("scalar owner association differs")
      end
      observation
    end

    private def ref!(reference : DiagnosticReplayTokenRef, kind : String, text : String? = nil) : DiagnosticRenderedToken
      entry = @journal.entry!(reference)
      unless entry.lexical_mode == @input.lexical_mode && entry.token_kind == kind && (text.nil? || entry.token_text == text)
        raise ArgumentError.new("scalar grammar token differs")
      end
      @journal.literal_entry!(entry.input_start, entry.input_end, kind, @input.lexical_mode)
    end

    private def skip!(cursor : Int32, allow_newline : Bool) : Int32
      loop do
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        permitted = token.token_kind == "SPACE" || (allow_newline && token.token_kind == "NEWLINE") ||
                    {"SKIPPED_COMMENT", "SKIPPED_DOC_COMMENT", "SKIPPED_LOC_PRAGMA"}.includes?(token.token_kind)
        return cursor unless permitted
        raise ArgumentError.new("unwitnessed grammar gap") unless token.input_end > cursor
        cursor = token.input_end
      end
    end

    private def token!(cursor : Int32, kind : String) : DiagnosticRenderedToken
      token = @journal.entry_at!(cursor, @input.lexical_mode)
      raise ArgumentError.new("scalar grammar token differs") unless token.token_kind == kind && token.input_end > cursor
      token
    end

    private def scalar!(node : ASTNode, field : String, index : Int32, cursor : Int32) : {String, Int32}
      token = token!(cursor, "DELIMITER_START")
      state = token.delimiter
      raise ArgumentError.new("scalar literal is not a string") unless state && state.kind == "STRING"
      value, start, finish = @owners.derive_key!(node, field, index)
      raise ArgumentError.new("scalar literal owner differs") unless start == cursor && finish > start
      {value, finish}
    end

    private def verify_require!(node : Require) : Nil
      observation = observation!(node, DiagnosticScalarGrammarKind::Require)
      first = ref!(observation.first, "IDENT", "require")
      raise ArgumentError.new("invalid require association") unless observation.open.nil? && observation.expression.nil?
      cursor = skip!(first.input_end, false)
      value, finish = scalar!(node, "string", 0, cursor)
      raise ArgumentError.new("require value differs") unless value == node.string
      close = ref!(observation.close, "DELIMITER_END")
      raise ArgumentError.new("require literal close differs") unless close.input_end == finish
      after = @journal.entry!(observation.after)
      raise ArgumentError.new("require return token differs") unless after == @journal.entry_at!(skip!(finish, false), @input.lexical_mode)
      @verified.add(node.object_id)
    end

    private def verify_asm!(node : Asm) : Nil
      observation = observation!(node, DiagnosticScalarGrammarKind::Asm)
      first = ref!(observation.first, "IDENT", "asm")
      opening_ref = observation.open || raise ArgumentError.new("asm opening association missing")
      opening = ref!(opening_ref, "(")
      raise ArgumentError.new("asm opening differs") unless opening.input_start == skip!(first.input_end, false)
      cursor = skip!(opening.input_end, true)
      text, finish = scalar!(node, "text", 0, cursor)
      raise ArgumentError.new("asm text differs") unless text == node.text
      cursor = skip!(finish, true)
      section = 0
      outputs = 0
      inputs = 0
      clobbers = 0
      options = 0
      flags = Set(String).new
      loop do
        token = @journal.entry_at!(cursor, @input.lexical_mode)
        break if token.token_kind == ")"
        case token.token_kind
        when ":"  then section += 1
        when "::" then section += 2
        else                       raise ArgumentError.new("invalid asm section separator")
        end
        raise ArgumentError.new("invalid asm section separator") unless token.input_end > cursor
        cursor = skip!(token.input_end, true)
        break if section > 4
        while @journal.entry_at!(cursor, @input.lexical_mode).token_kind == "DELIMITER_START"
          case section
          when 1
            operand = node.outputs.try(&.[outputs]?) || raise ArgumentError.new("asm outputs differ")
            cursor = verify_operand!(operand, cursor)
            outputs += 1
          when 2
            operand = node.inputs.try(&.[inputs]?) || raise ArgumentError.new("asm inputs differ")
            cursor = verify_operand!(operand, cursor)
            inputs += 1
          when 3
            value, end_offset = scalar!(node, "clobbers", clobbers, cursor)
            raise ArgumentError.new("asm clobbers differ") unless node.clobbers.try(&.[clobbers]?) == value
            clobbers += 1
            cursor = skip!(end_offset, true)
          when 4
            value, end_offset = scalar!(node, "options", options, cursor)
            raise ArgumentError.new("unknown asm option") unless {"volatile", "alignstack", "intel", "unwind"}.includes?(value)
            flags.add(value)
            options += 1
            cursor = skip!(end_offset, true)
          else
            raise ArgumentError.new("invalid asm section")
          end
          comma = @journal.entry_at!(cursor, @input.lexical_mode)
          cursor = skip!(comma.input_end, true) if comma.token_kind == ","
        end
      end
      close = ref!(observation.close, ")")
      raise ArgumentError.new("asm closing differs") unless close.input_start == cursor
      raise ArgumentError.new("asm outputs differ") unless (node.outputs.try(&.size) || 0) == outputs && (outputs > 0 || node.outputs.nil?)
      raise ArgumentError.new("asm inputs differ") unless (node.inputs.try(&.size) || 0) == inputs && (inputs > 0 || node.inputs.nil?)
      raise ArgumentError.new("asm clobbers differ") unless (node.clobbers.try(&.size) || 0) == clobbers && (clobbers > 0 || node.clobbers.nil?)
      unless node.volatile? == flags.includes?("volatile") && node.alignstack? == flags.includes?("alignstack") &&
             node.intel? == flags.includes?("intel") && node.can_throw? == flags.includes?("unwind")
        raise ArgumentError.new("asm options differ")
      end
      option_keys = node.diagnostic_literal_names.keys.select { |key| key[0] == "options" }.to_set
      raise ArgumentError.new("asm option occurrences differ") unless option_keys == (0...options).map { |i| {"options", i} }.to_set
      after = @journal.entry!(observation.after)
      raise ArgumentError.new("asm return token differs") unless after == @journal.entry_at!(skip!(close.input_end, false), @input.lexical_mode)
      @verified.add(node.object_id)
    end

    private def verify_operand!(node : AsmOperand, cursor : Int32) : Int32
      observation = observation!(node, DiagnosticScalarGrammarKind::AsmOperand)
      first = ref!(observation.first, "DELIMITER_START")
      raise ArgumentError.new("asm operand owner differs") unless first.input_start == cursor
      value, finish = scalar!(node, "constraint", 0, cursor)
      raise ArgumentError.new("asm constraint differs") unless value == node.constraint
      opening_ref = observation.open || raise ArgumentError.new("asm operand opening missing")
      opening = ref!(opening_ref, "(")
      raise ArgumentError.new("asm operand opening differs") unless opening.input_start == skip!(finish, false)
      expression = observation.expression || raise ArgumentError.new("asm expression association missing")
      raise ArgumentError.new("asm expression association differs") unless node.exp.same?(expression)
      expression_ref = observation.expression_first || raise ArgumentError.new("asm expression association missing")
      expression_first = @journal.entry!(expression_ref)
      unless expression_first == @journal.entry_at!(skip!(opening.input_end, true), @input.lexical_mode)
        raise ArgumentError.new("asm expression start differs")
      end
      closing = ref!(observation.close, ")")
      raise ArgumentError.new("asm expression bounds differ") unless closing.input_start >= expression_first.input_start
      after_cursor = skip!(closing.input_end, true)
      after = @journal.entry!(observation.after)
      raise ArgumentError.new("asm operand return token differs") unless after == @journal.entry_at!(after_cursor, @input.lexical_mode)
      raise ArgumentError.new("duplicate asm operand") unless @verified.add?(node.object_id)
      after_cursor
    end
  end

  # The identity of one source capture, derived from its replay (C-M). The
  # caller's logical module never participates.
  class DiagnosticModuleIdentity
    getter source_unit : String
    getter declared : String?
    getter package : String?
    getter header : ModuleHeader?
    getter header_origin : DiagnosticOrigin::Written?
    getter header_segments : Array(String)

    def initialize(@source_unit : String, @declared : String?, @package : String?,
                   @header : ModuleHeader?, @header_origin : DiagnosticOrigin::Written?,
                   @header_segments : Array(String))
    end

    def header_offset : Int32?
      @header_origin.try(&.input_byte_offset)
    end

    # The module a Written origin at `offset` must carry. Each offset has one.
    def expected_module(offset : Int32) : String
      if (declared = @declared) && (start = header_offset) && offset >= start
        declared
      else
        @source_unit
      end
    end

    def self.from(root : ASTNode, input : AcceptedCaptureInput,
                  journal : DiagnosticReplayJournal) : DiagnosticModuleIdentity
      raise ArgumentError.new("EntryBuffer capture has no written identity rule") unless input.kind.source_file?
      raise ArgumentError.new("caller-supplied module identity") unless input.logical_module.nil?
      file = input.original_file || raise ArgumentError.new("source capture requires original file identity")
      source_unit = "source-file:#{file}"
      package = input.package
      mode = input.lexical_mode
      expressions = case root
                    when Expressions then root.keyword.none? ? root.expressions : [root] of ASTNode
                    else                  [root] of ASTNode
                    end
      # The header follows an optional unsafe file mark, as apply_module_header places it.
      if mode == "Iyi" && (first = expressions.first?) && first.is_a?(Annotation) && Parser.iyi_unsafe_file_mark?(first)
        expressions = expressions[1..]
      end
      header = expressions.first?
      return new(source_unit, nil, package, nil, nil, [] of String) unless header.is_a?(ModuleHeader)
      origin = header.diagnostic_origin.as?(DiagnosticOrigin::Written) ||
               raise ArgumentError.new("module header lacks written origin")
      raise ArgumentError.new("module header origin has the wrong anchor") unless origin.valid_for_anchor?("ModuleHeader", "keyword")
      raise ArgumentError.new("module header origin is in another file") unless origin.source_file == file
      start = origin.input_byte_offset
      keyword_scanned = journal.starts_at(start).any? do |entry|
        entry.input_end == start + "module".bytesize && entry.token_text == "module" && entry.lexical_mode == mode
      end
      raise ArgumentError.new("module header keyword is not a scanned token") unless keyword_scanned
      declared = Parser.iyi_package_segments(package, header.path).join("/")
      raise ArgumentError.new("module header origin carries the wrong module") unless origin.source_module == declared
      header.path.each_with_index do |segment, index|
        slot = DiagnosticNameSlot.new(DiagnosticNameSlotKind::ModuleSegment, index)
        value = header.diagnostic_name_slots[slot]?.try(&.first?)
        observed = value.as?(DiagnosticNameValue::Observed) || raise ArgumentError.new("module segment is not an observed token")
        token = observed.source_token
        raise ArgumentError.new("module segment is not a scanned token") unless token.raw_text == segment && journal.scanned?(token)
      end
      new(source_unit, declared, package, header, origin, header.path.dup)
    end
  end

  # The replay-bound walk accepts literal fields only when the independently
  # recorded owner, grammar and lexical evidence bind their exact occurrences.
  class DiagnosticEvidenceBinding < DiagnosticRecordedEvidenceInputCheck
    def initialize(input : AcceptedCaptureInput, journal : DiagnosticReplayJournal,
                   identity : DiagnosticModuleIdentity, structural : Set(UInt64),
                   bundle : DiagnosticLiteralReplayAssociations? = nil)
      super(input, journal, identity, structural, bundle)
    end
  end

  # The ledger of recorded authorities for one run. Authorities are appended in
  # execution order. The ledger freezes before any binding, so every sequence is
  # known when the first claim binds.
  class DiagnosticCaptureLedger
    @authorities = [] of DiagnosticCaptureAuthority
    @frozen = false

    def authorities : Array(DiagnosticCaptureAuthority)
      @authorities.dup
    end

    def size : Int32
      @authorities.size
    end

    def authority(key : String) : DiagnosticCaptureAuthority?
      @authorities.find { |recorded| recorded.capture_key == key }
    end

    def frozen? : Bool
      @frozen
    end

    def freeze! : Nil
      @frozen = true
    end

    # Only an authority this ledger minted, at its next sequence, while open.
    def append!(authority : DiagnosticCaptureAuthority) : Nil
      raise ArgumentError.new("capture ledger is frozen") if @frozen
      raise ArgumentError.new("capture authority belongs to another ledger") unless authority.ledger.same?(self)
      raise ArgumentError.new("capture authority is out of sequence") unless authority.sequence == @authorities.size
      @authorities << authority
    end

    # Binds one claim against its recorded authority, after the ledger is frozen.
    def bind!(claim : AcceptedCaptureInput, authority : DiagnosticCaptureAuthority) : DiagnosticBoundCapture
      raise ArgumentError.new("capture ledger must be frozen before binding") unless @frozen
      raise ArgumentError.new("capture authority belongs to another ledger") unless authority.ledger.same?(self)
      DiagnosticCaptureBinding.bind!(claim, authority)
    end
  end

  # The only mint for a capture authority. `record_source` runs the live parser's
  # entry itself, takes the key from that parser's snapshot before the entry runs,
  # and digests the tree the entry returned. Nothing here is read from a claim.
  class DiagnosticCaptureAuthority
    getter ledger : DiagnosticCaptureLedger
    getter sequence : Int32
    getter kind : DiagnosticCaptureInputKind
    getter capture_key : String
    getter ast_sha256 : String

    private def initialize(@ledger : DiagnosticCaptureLedger, @sequence : Int32,
                           @kind : DiagnosticCaptureInputKind, @capture_key : String, @ast_sha256 : String)
    end

    # Records one SourceFile: the parser's filename must name a real file whose
    # bytes the parser was given, otherwise the capture is an EntryBuffer and is
    # refused until its identity rule lands.
    def self.record_source(ledger : DiagnosticCaptureLedger, parser : Parser,
                           mode : Parser::ParseMode = Parser::ParseMode::Normal) : {ASTNode, AcceptedCaptureInput, DiagnosticCaptureAuthority}
      raise ArgumentError.new("capture ledger is frozen") if ledger.frozen?
      contract = parser.parse_ahead_contract
      raise ArgumentError.new("parser state is not eligible for capture") if contract.nil?
      filename = JSON.parse(contract)["filename"].as_s? ||
                 raise ArgumentError.new("EntryBuffer capture has no written identity rule")
      unless !filename.empty? && File.file?(filename) && parser.parse_ahead_input_matches?(File.read(filename))
        raise ArgumentError.new("EntryBuffer capture has no written identity rule")
      end
      current = parser.diagnostic_source_unit
      unless current.nil? || current == "source-file:#{filename}"
        raise ArgumentError.new("capture source unit disagrees with its classification")
      end
      parser.diagnostic_capture = true
      parser.diagnostic_source_file = filename
      claim = parser.diagnostic_capture_input(DiagnosticCaptureInputKind::SourceFile, nil,
        DiagnosticCaptureParseEntry::Parse, mode)
      root = claim.replay_entry(parser)
      stream = DiagnosticAstFrameStream.new(root)
      stream.stream { |_| }
      authority = new(ledger, ledger.size, DiagnosticCaptureInputKind::SourceFile, claim.capture_key, stream.ast_sha256)
      DiagnosticCaptureRefs.stamp!(root, authority.capture_key)
      ledger.append!(authority)
      {root, claim, authority}
    end
  end

  record DiagnosticBoundCapture, input : AcceptedCaptureInput, authority : DiagnosticCaptureAuthority, root : ASTNode,
    identity : DiagnosticModuleIdentity, journal : DiagnosticReplayJournal

  # J2 (C-B), revised for D3: the only path from a claim to a bound capture. The
  # claim binds only against an authority with an equal key, and only if its
  # replay reproduces that key, runs the same entry and yields the same digest.
  module DiagnosticCaptureBinding
    def self.bind!(input : AcceptedCaptureInput, authority : DiagnosticCaptureAuthority) : DiagnosticBoundCapture
      ledger = authority.ledger
      raise ArgumentError.new("capture ledger must be frozen before binding") unless ledger.frozen?
      unless ledger.authorities.any? { |recorded| recorded.same?(authority) }
        raise ArgumentError.new("capture authority is not in its ledger")
      end
      raise ArgumentError.new("capture key differs from its authority") unless input.capture_key == authority.capture_key
      raise ArgumentError.new("EntryBuffer capture has no written identity rule") unless authority.kind.source_file?
      parser = input.replay_parser
      parser.enable_diagnostic_observations
      unless input.replay_capture_input(parser).capture_key == input.capture_key
        raise ArgumentError.new("capture replay does not reproduce its parser contract")
      end
      root = input.replay_entry(parser)
      stream = DiagnosticAstFrameStream.new(root)
      stream.stream { |_| }
      raise ArgumentError.new("replay AST digest differs") unless stream.ast_sha256 == authority.ast_sha256
      DiagnosticCaptureRefs.stamp!(root, authority.capture_key)
      journal = DiagnosticReplayJournal.new(parser.diagnostic_lexical_observations)
      identity = DiagnosticModuleIdentity.from(root, input, journal)
      structural = DiagnosticUnnamedParamBinder.new(input, journal).verify!(root)
      bundle = DiagnosticLiteralReplayAssociations.new(input, journal, parser, root)
      DiagnosticEvidenceBinding.new(input, journal, identity, structural, bundle).verify!(root)
      DiagnosticBoundCapture.new(input, authority, root, identity, journal)
    end
  end

  # E2 and E3 (ruling): rebuilds the event of one witness span from the pinned
  # emission records, and refuses any byte those records do not attribute. A
  # recorded event must equal the rebuilt event exactly.
  module DiagnosticWitnessEventReplay
    def self.expected_event(start : Int32, finish : Int32, kind : String, raw : String, mode : String,
                            generated : Array(DiagnosticGeneratedText),
                            names : Array(DiagnosticMacroNameFragment)) : DiagnosticTokenEvent
      raise ArgumentError.new("witness event span is empty") unless start >= 0 && finish > start
      raise ArgumentError.new("witness event differs from macro emission") unless raw.bytesize == finish - start
      parts = [] of DiagnosticEmissionPart
      cursor = start
      while cursor < finish
        name = names.find { |fragment| fragment.start_offset == cursor && fragment.end_offset > cursor && fragment.end_offset <= finish }
        if name
          raise ArgumentError.new("name splice requires a CONST or IDENT witness") unless {"CONST", "IDENT"}.includes?(kind)
          parts << DiagnosticEmissionPart::NameSplice.new(name.start_offset, name.end_offset, name.emitter_origin, name.source_name)
          cursor = name.end_offset
          next
        end
        covering = generated.find { |text| text.start_offset <= cursor && text.end_offset > cursor }
        raise ArgumentError.new("witness bytes not attributed by macro emission") unless covering
        piece_end = Math.min(covering.end_offset, finish)
        last = parts.last?
        if last.is_a?(DiagnosticEmissionPart::Generated) && last.end_offset == cursor &&
           last.producer == covering.producer && last.emitter_origin == covering.emitter_origin
          parts[parts.size - 1] = DiagnosticEmissionPart::Generated.new(last.start_offset, piece_end, last.emitter_origin, last.producer)
        else
          parts << DiagnosticEmissionPart::Generated.new(cursor, piece_end, covering.emitter_origin, covering.producer)
        end
        cursor = piece_end
      end
      DiagnosticTokenEvent.new(start, finish, kind, raw, mode, DiagnosticTokenSelection::Whole, parts)
    end

    def self.verify!(witness : DiagnosticOperatorWitness, mode : String,
                     generated : Array(DiagnosticGeneratedText), names : Array(DiagnosticMacroNameFragment)) : Nil
      raise ArgumentError.new("witness selection is not whole") unless witness.selection.whole?
      expected = expected_event(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text, mode, generated, names)
      raise ArgumentError.new("witness event differs from macro emission") unless witness.event == expected
    end
  end

  # Unnamed-parameter binder (ruling U1-U6). The Written chain is bound here, and
  # every witness event is null (U6). An Expanded unnamed parameter needs the replayed
  # expansion pragmas, with E1 substitution of the anchor's token event and E2 events
  # on every non-anchor witness (contract X). Until that is wired it is held, and
  # a ShortBlockArgument has no binding in this slice.
  class DiagnosticUnnamedParamBinder
    record Candidate, origin : DiagnosticOrigin::DerivedName, fundef : FunDef, index : Int32, inside_lib : Bool
    @ordered : Array(DiagnosticRenderedToken)

    def initialize(@input : AcceptedCaptureInput, @journal : DiagnosticReplayJournal)
      @owners = {} of UInt64 => Tuple(FunDef, Int32, Bool)
      @candidates = [] of Candidate
      @ordered = @journal.entries.uniq.sort_by { |entry| {entry.input_start, entry.input_end} }
    end

    # Returns the object ids of every StructuralName origin this binder verified.
    def verify!(root : ASTNode) : Set(UInt64)
      collect(root, false, 0)
      verified = Set(UInt64).new
      @candidates.each do |candidate|
        verify_candidate!(candidate)
        verified << candidate.origin.object_id
      end
      verified
    end

    private def collect(node : ASTNode, inside_lib : Bool, depth : Int32) : Nil
      raise ArgumentError.new("recorded evidence exceeds depth limit") if depth > DiagnosticRecordedEvidenceInputCheck::MAX_DEPTH
      if node.is_a?(FunDef)
        node.args.each_with_index { |arg, index| @owners[arg.object_id] = {node, index, inside_lib} }
      end
      node.each_diagnostic_name_slot do |_, values|
        values.each do |value|
          next unless value.is_a?(DiagnosticNameValue::Derived) && value.origin.derivation_kind == "StructuralName"
          fundef, index, owner_lib = @owners[node.object_id]? || raise ArgumentError.new("structural witness differs")
          @candidates << Candidate.new(value.origin, fundef, index, owner_lib)
        end
      end
      child_lib = node.is_a?(LibDef) || (inside_lib && node.is_a?(Expressions))
      DiagnosticDirectChildFields.each(node) { |_, _, _, child| collect(child, child_lib, depth + 1) }
    end

    private def verify_candidate!(candidate : Candidate) : Nil
      origin = candidate.origin
      case origin.structural_production
      when DiagnosticStructuralProduction::UnnamedFunParameter then nil
      when DiagnosticStructuralProduction::ShortBlockArgument
        raise ArgumentError.new("short block argument binding is held until the printer fix lands")
      else
        raise ArgumentError.new("invalid structural production")
      end
      anchor = origin.structural_anchor || raise ArgumentError.new("invalid structural anchor")
      if anchor.is_a?(DiagnosticOrigin::Expanded)
        raise ArgumentError.new("expanded unnamed parameter requires replayed expansion pragmas (contract X)")
      end
      raise ArgumentError.new("invalid structural anchor") unless anchor.is_a?(DiagnosticOrigin::Written)
      raise ArgumentError.new("invalid structural anchor") unless anchor.valid_for_anchor?("FunDef", "keyword") && anchor == candidate.fundef.diagnostic_origin
      raise ArgumentError.new("unnamed parameter outside lib fun") unless candidate.inside_lib
      mode = @input.lexical_mode
      start = anchor.input_byte_offset
      owner_arg = candidate.fundef.args[candidate.index]? || raise ArgumentError.new("structural witness differs")
      raise ArgumentError.new("structural witness differs") unless owner_arg.name.empty?
      unless origin.structural_input_sha256 == @input.input_sha256 &&
             origin.structural_input_bytesize == @input.input_bytesize &&
             origin.structural_lexical_mode == mode
        raise ArgumentError.new("structural witnesses use different inputs")
      end
      raise ArgumentError.new("invalid structural anchor") unless @journal.scanned_span?(start, start + 3, "IDENT", "fun", mode)

      witnesses = origin.structural_witnesses
      raise ArgumentError.new("structural witness differs") unless witnesses.size == 2 && origin.structural_fresh_index.nil?
      separator = witnesses[0]
      head = witnesses[1]
      witnesses.each do |witness|
        raise ArgumentError.new("invalid structural witness provenance") unless witness.event.nil?
        raise ArgumentError.new("structural witness is not a scanned token") unless @journal.scanned_span?(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text, mode)
      end
      raise ArgumentError.new("anchor does not precede witnesses") unless start < separator.input_start && separator.input_start < head.input_start

      # The list opener is the first "(" after the name and the optional "= real_name".
      trivia = {"SPACE", "NEWLINE", "COMMENT", "EOF"}
      tokens = @ordered.select { |entry| entry.input_start >= start + 3 && !trivia.includes?(entry.token_kind) }
      tokens[0]? || raise ArgumentError.new("separator outside parameter list")
      index = 1
      if tokens[1]?.try(&.token_text) == "="
        real = tokens[2]? || raise ArgumentError.new("separator outside parameter list")
        if {"IDENT", "CONST"}.includes?(real.token_kind)
          index = 3
        elsif real.token_kind == "DELIMITER_START"
          # A string real name spans its DELIMITER_START through the matching DELIMITER_END.
          nest = 0
          index = 2
          while index < tokens.size
            kind = tokens[index].token_kind
            nest += 1 if kind == "DELIMITER_START"
            nest -= 1 if kind == "DELIMITER_END"
            index += 1
            break if nest == 0
          end
          raise ArgumentError.new("separator outside parameter list") unless nest == 0
        else
          raise ArgumentError.new("separator outside parameter list")
        end
      end
      opener = tokens[index]? || raise ArgumentError.new("separator outside parameter list")
      raise ArgumentError.new("separator outside parameter list") unless opener.token_text == "("
      depth = 0
      separator_index = 0
      found = -1
      position = index
      while position < tokens.size
        token = tokens[position]
        if token.input_start == separator.input_start
          raise ArgumentError.new("structural witness differs") unless token.token_text == separator.raw_text && token.token_kind == separator.token_kind
          raise ArgumentError.new("separator outside parameter list") unless position == index || (token.token_text == "," && depth == 1)
          separator_index += 1 if token.token_text == "," && depth == 1
          found = position
          break
        end
        case token.token_text
        when "(", "[", "{" then depth += 1
        when ")", "]", "}"
          depth -= 1
          raise ArgumentError.new("separator outside parameter list") if depth <= 0
        when "," then separator_index += 1 if depth == 1
        end
        position += 1
      end
      raise ArgumentError.new("separator outside parameter list") if found < 0

      # The slot ends at the token that closes the list, or at a depth-1 comma after the separator.
      slot_end = -1
      depth = 1
      position = found + 1
      while position < tokens.size
        token = tokens[position]
        case token.token_text
        when "(", "[", "{" then depth += 1
        when ")", "]", "}"
          depth -= 1
          if depth == 0
            slot_end = token.input_start
            break
          end
        when ","
          if depth == 1
            slot_end = token.input_start
            break
          end
        end
        position += 1
      end
      raise ArgumentError.new("separator outside parameter list") if slot_end < 0

      # The head is the first journal entry after the separator that is not SPACE or NEWLINE.
      following = @ordered.find { |entry| entry.input_start >= separator.input_end && !{"SPACE", "NEWLINE"}.includes?(entry.token_kind) }
      raise ArgumentError.new("unnamed parameter head is not the first type token") unless following && following.input_start == head.input_start
      raise ArgumentError.new("structural witness differs") unless following.token_kind == head.token_kind && following.token_text == head.raw_text
      raise ArgumentError.new("unnamed parameter head is not the first type token") if following.token_kind == "IDENT" || following.token_text == "..."

      raise ArgumentError.new("structural witness differs") unless separator_index == candidate.index
      restriction = owner_arg.restriction || raise ArgumentError.new("structural witness differs")
      evidence = [] of {Int32, Int32}
      structural_restriction_evidence(restriction, mode, 0, evidence)
      raise ArgumentError.new("structural witness differs") if evidence.empty?
      evidence.each do |span|
        raise ArgumentError.new("structural witness differs") unless head.input_start <= span[0] && span[0] < span[1] && span[1] <= slot_end
      end
      first = evidence.min_of { |span| span[0] }
      @ordered.each do |entry|
        next if entry.input_start < head.input_start || entry.input_start >= first
        next if trivia.includes?(entry.token_kind)
        raise ArgumentError.new("structural witness differs") unless {"::", "(", "->"}.includes?(entry.token_text)
      end
    end

    # U4 evidence for a restriction subtree: each Written origin (which must start a
    # scanned token), each scanned Observed token and each derived witness, appended as spans.
    private def structural_restriction_evidence(node : ASTNode, mode : String, depth : Int32, spans : Array({Int32, Int32})) : Nil
      raise ArgumentError.new("structural witness differs") if depth > DiagnosticRecordedEvidenceInputCheck::MAX_DEPTH
      if origin = node.diagnostic_origin
        written = origin
        while written.is_a?(DiagnosticOrigin::Synthetic)
          written = written.parent_origin
        end
        if written.is_a?(DiagnosticOrigin::Written)
          entries = @journal.starts_at(written.input_byte_offset)
          raise ArgumentError.new("structural witness differs") if entries.empty?
          entries.each { |entry| spans << {entry.input_start, entry.input_end} }
        end
      end
      node.each_diagnostic_name_slot do |_, values|
        values.each do |value|
          case value
          when DiagnosticNameValue::Observed
            token = value.source_token
            raise ArgumentError.new("structural witness differs") unless @journal.scanned?(token)
            spans << {token.input_start, token.input_end}
          when DiagnosticNameValue::Derived
            (value.origin.operator_witnesses + value.origin.structural_witnesses).each do |witness|
              raise ArgumentError.new("structural witness differs") unless @journal.scanned_span?(witness.input_start, witness.input_end, witness.token_kind, witness.raw_text, mode)
              spans << {witness.input_start, witness.input_end}
            end
          end
        end
      end
      DiagnosticDirectChildFields.each(node) { |_, _, _, child| structural_restriction_evidence(child, mode, depth + 1, spans) }
    end
  end
end
