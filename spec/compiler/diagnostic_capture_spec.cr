require "../support/syntax"

describe Iyi::DiagnosticPathSnapshot do
  it "freezes every original path segment independently of later AST mutation" do
    source = "Root::Thing"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    snapshot = Iyi::DiagnosticPathSnapshot.new(path, input)
    original = snapshot.bytes
    names = JSON.parse(original)["names"].as_a.map { |field| field["value"].as_s }
    names.should eq(["Root", "Thing"])
    path.names[0] = "Changed"
    path.names.pop
    snapshot.bytes.should eq(original)
    snapshot.sha256.should eq(::Crystal::Digest::SHA256.hexdigest(original))
  end

  it "owns input and returned snapshot bytes instead of sharing strings" do
    source = String.new("Root::Thing".to_slice)
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    snapshot = Iyi::DiagnosticPathSnapshot.new(path, input)
    expected = snapshot.bytes
    source.to_unsafe[0] = 'X'.ord.to_u8
    input.input.should eq("Root::Thing")
    working = snapshot.bytes
    working.to_unsafe[0] = 'X'.ord.to_u8
    snapshot.bytes.should eq(expected)
    original_digest = snapshot.sha256
    returned_digest = snapshot.sha256
    returned_digest.to_unsafe[0] = 'z'.ord.to_u8
    snapshot.sha256.should eq(original_digest)
    original_file = input.original_file.not_nil!
    returned_file = input.original_file.not_nil!
    returned_file.to_unsafe[0] = 'X'.ord.to_u8
    input.original_file.should eq(original_file)
    original_policy = input.warning_policy_json
    policy_copy = input.warning_policy_json
    policy_copy.to_unsafe[0] = 'X'.ord.to_u8
    parser.warnings.error_on_warnings = true
    input.warning_policy_json.should eq(original_policy)
    input.warning_policy.error_on_warnings?.should be_false
    original_contract = input.fresh_parser_contract
    contract_copy = input.fresh_parser_contract
    contract_copy.to_unsafe[0] = 'X'.ord.to_u8
    input.fresh_parser_contract.should eq(original_contract)
  end

  it "refuses a path whose actual name has lost its evidence" do
    source = "Root::Thing"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    path.names << "Missing"
    expect_raises(ArgumentError, /does not cover all segments/) do
      Iyi::DiagnosticPathSnapshot.new(path, input)
    end
  end

  it "rejects missing evidence for an actual path segment" do
    source = "Root::Thing"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    path = parser.parse.as(Iyi::Path)
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(input)
    checker.verify!(path)
    slots = path.diagnostic_name_slots
    slots.delete(Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 1))
    path.diagnostic_name_slots = slots
    expect_raises(ArgumentError, /missing source evidence/) { checker.verify!(path) }
  end

  it "binds an implicit external argument name to the recorded internal name" do
    source = "def f(arg); end"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.cr"
    parser.diagnostic_source_file = "/spec/path_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    definition = parser.parse.as(Iyi::Def)
    definition.args.first.diagnostic_external_explicit.should be_false
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(input)
    checker.verify!(definition)
    definition.args.first.external_name = "changed"
    expect_raises(ArgumentError, /invalid implicit external-name observation/) { checker.verify!(definition) }
  end

  it "binds a forall bound-map key to its declared free variable" do
    source = "def f(x : T) forall T : Show\nend"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.iyi"
    parser.diagnostic_source_file = "/spec/path_capture.iyi"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    definition = parser.parse.as(Iyi::Def)
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(input)
    checker.verify!(definition)
    definition.free_var_bounds.not_nil!["Unknown"] = Iyi::Path.new("Show")
    expect_raises(ArgumentError, /bound lacks original declaration/) { checker.verify!(definition) }
  end

  it "rejects a trait associated-type summary that differs from its body" do
    source = "trait Sequence\n  type Item\nend"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.iyi"
    parser.diagnostic_source_file = "/spec/path_capture.iyi"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    trait = parser.parse.as(Iyi::TraitDef)
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(input)
    checker.verify!(trait)
    trait.assoc_types.not_nil![0] = "Other"
    expect_raises(ArgumentError, /trait associated-type projection mismatch/) { checker.verify!(trait) }
  end

  it "checks imported path and selected-name observations on their owners" do
    source = "import std/json::{Parser}"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/path_capture.iyi"
    parser.diagnostic_source_file = "/spec/path_capture.iyi"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    root = parser.parse
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end
end

describe Iyi::DiagnosticAstFieldSchema do
  it "classifies bounds and annotations but refuses unclassified fields" do
    Iyi::DiagnosticAstFieldSchema.classify("Def", "where_bounds").should eq(Iyi::DiagnosticAstFieldClass::NamedChildMap)
    Iyi::DiagnosticAstFieldSchema.classify("Def", "free_var_bounds").should eq(Iyi::DiagnosticAstFieldClass::NamedChildMap)
    Iyi::DiagnosticAstFieldSchema.classify("Arg", "parsed_annotations").should eq(Iyi::DiagnosticAstFieldClass::ChildList)
    expect_raises(ArgumentError, /unclassified AST field/) do
      Iyi::DiagnosticAstFieldSchema.classify("Path", "unknown")
    end
  end
end

describe Iyi::DiagnosticDirectChildFields do
  it "reads argument annotations and both definition bound maps directly" do
    annotation = Iyi::Annotation.new(Iyi::Path.new("Marker"))
    argument = Iyi::Arg.new("arg", parsed_annotations: [annotation])
    definition = Iyi::Def.new("f", [argument])
    definition.free_var_bounds = {"T" => Iyi::Path.new("Trait").as(Iyi::ASTNode)}
    definition.where_bounds = {"U" => Iyi::Path.new("Other").as(Iyi::ASTNode)}

    argument_fields = [] of {String, Int32?, String?, Iyi::ASTNode}
    Iyi::DiagnosticDirectChildFields.each(argument) do |field, index, key, child|
      argument_fields << {field, index, key, child}
    end
    argument_fields.should contain({"parsed_annotations", 0, nil, annotation})

    definition_fields = [] of {String, Int32?, String?, Iyi::ASTNode}
    Iyi::DiagnosticDirectChildFields.each(definition) do |field, index, key, child|
      definition_fields << {field, index, key, child}
    end
    definition_fields.map { |field| {field[0], field[2]} }.should contain({"free_var_bounds", "T"})
    definition_fields.map { |field| {field[0], field[2]} }.should contain({"where_bounds", "U"})
  end
end

describe Iyi::DiagnosticDirectNameFields do
  it "enumerates actual path segments and symbol bytes without contributor selection" do
    path_fields = [] of {String, Int32?, String?, String}
    Iyi::DiagnosticDirectNameFields.each(Iyi::Path.new(["Root", "Thing"])) do |field, index, key, value|
      path_fields << {field, index, key, value}
    end
    path_fields.should eq([
      {"names", 0, nil, "Root"},
      {"names", 1, nil, "Thing"},
    ])

    symbol_fields = [] of {String, Int32?, String?, String}
    Iyi::DiagnosticDirectNameFields.each(Iyi::SymbolLiteral.new("name")) do |field, index, key, value|
      symbol_fields << {field, index, key, value}
    end
    symbol_fields.should contain({"value", nil, nil, "name"})
  end
end

describe Iyi::DiagnosticDirectPresenceFields do
  it "distinguishes absent and present-empty named argument lists" do
    generic = Iyi::Generic.new(Iyi::Path.new("Foo"), [] of Iyi::ASTNode)
    absent = {} of String => Iyi::DiagnosticFieldPresence
    Iyi::DiagnosticDirectPresenceFields.each(generic) { |field, state| absent[field] = state }
    absent["named_args"].should eq(Iyi::DiagnosticFieldPresence::Absent)
    absent_capture = Iyi::DiagnosticAstInventorySnapshot.new(generic).bytes
    generic.named_args = [] of Iyi::NamedArgument
    present = {} of String => Iyi::DiagnosticFieldPresence
    Iyi::DiagnosticDirectPresenceFields.each(generic) { |field, state| present[field] = state }
    present["named_args"].should eq(Iyi::DiagnosticFieldPresence::Empty)
    present_capture = Iyi::DiagnosticAstInventorySnapshot.new(generic).bytes
    absent_capture.should_not eq(present_capture)
    generic.suffix = Iyi::Generic::Suffix::Question
    Iyi::DiagnosticAstInventorySnapshot.new(generic).bytes.should_not eq(present_capture)
  end
end

describe Iyi::DiagnosticAstInventorySnapshot do
  it "freezes direct nested names before mutation" do
    path = Iyi::Path.new(["Root", "Thing"])
    generic = Iyi::Generic.new(path, [Iyi::Path.new("Other")] of Iyi::ASTNode)
    capture = Iyi::DiagnosticAstInventorySnapshot.new(generic)
    before = capture.bytes
    children = JSON.parse(before)["children"].as_a
    segments = children.first["node"]["names"].as_a
    segments.map { |entry| Base64.decode_string(entry["value_base64"].as_s) }.should eq(["Root", "Thing"])
    path.names.pop
    capture.bytes.should eq(before)
    owner = [Iyi::DiagnosticInventoryStep.new("name", nil, nil)]
    field = Iyi::DiagnosticInventoryStep.new("names", 1, nil)
    String.new(capture.resolve_name(owner, field)).should eq("Thing")
    expect_raises(ArgumentError, /unknown inventory coordinate/) do
      capture.resolve_name(owner, Iyi::DiagnosticInventoryStep.new("names", 2, nil))
    end
  end

  it "records repeated references to the same AST node without losing identity" do
    shared = Iyi::Path.new("Shared")
    root = Iyi::Generic.new(shared, [shared] of Iyi::ASTNode)
    inventory = JSON.parse(Iyi::DiagnosticAstInventorySnapshot.new(root).bytes)
    children = inventory["children"].as_a
    children[0]["node"]["owner_id"].should eq(children[1]["node"]["owner_id"])
  end

  it "rejects cycles instead of walking a back-reference indefinitely" do
    definition = Iyi::Def.new("f")
    definition.body = definition
    expect_raises(ArgumentError, /cyclic AST inventory/) do
      Iyi::DiagnosticAstInventorySnapshot.new(definition)
    end
  end

  it "retains decoded symbol bytes that are not UTF-8" do
    bytes = Bytes[0xff, 0x61]
    capture = Iyi::DiagnosticAstInventorySnapshot.new(Iyi::SymbolLiteral.new(String.new(bytes)))
    field = Iyi::DiagnosticInventoryStep.new("value", nil, nil)
    capture.resolve_name([] of Iyi::DiagnosticInventoryStep, field).should eq(bytes)
  end

  it "distinguishes absent name evidence from present-empty evidence" do
    path = Iyi::Path.new("Root")
    absent = JSON.parse(Iyi::DiagnosticAstInventorySnapshot.new(path).bytes)
    absent["name_slots"].raw.should be_nil
    path.diagnostic_name_slots = {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue)
    present = JSON.parse(Iyi::DiagnosticAstInventorySnapshot.new(path).bytes)
    present["name_slots"].as_a.should be_empty
  end

  it "records stored end-location absence rather than a derived child location" do
    right = Iyi::Path.new("Right")
    right.end_location = Iyi::Location.new("/spec/source.cr", 1, 9)
    expression = Iyi::And.new(Iyi::Path.new("Left"), right)
    expression.end_location.should_not be_nil
    inventory = JSON.parse(Iyi::DiagnosticAstInventorySnapshot.new(expression).bytes)
    inventory["end_location"].raw.should be_nil
  end
end

describe Iyi::DiagnosticLiteralInputChecks do
  it "binds literal byte observations to the original input and decoded value" do
    source = %q(f("\xFF": 1))
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/literal_input.cr"
    parser.diagnostic_source_file = "/spec/literal_input.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    root = parser.parse.as(Iyi::Call)
    arg = root.named_args.not_nil!.first
    checker = Iyi::DiagnosticRecordedEvidenceInputCheck.new(input)
    checker.verify!(root)
    literal = arg.diagnostic_literal_names[{"name", 0}]
    productions = arg.diagnostic_literal_productions[{"name", 0}]
    Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, productions, String.new(Bytes[0xff]), input)
    Iyi::DiagnosticLiteralInputChecks.verify_owner_field!(arg, "name", 0, input)
    expect_raises(ArgumentError, /invalid named argument literal field/) do
      Iyi::DiagnosticLiteralInputChecks.verify_owner_field!(arg, "external_name", 0, input)
    end
    expect_raises(ArgumentError, /decoded value mismatch/) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, productions, "x", input)
    end
    actual_segment = literal.segments.first
    false_segment = Iyi::DiagnosticLiteralSegment.new(actual_segment.start_offset, actual_segment.end_offset, "AAAA")
    altered = Iyi::DiagnosticParsedLiteral.new(literal.input_sha256, literal.input_bytesize, literal.lexical_mode,
      literal.decoded_base64, [false_segment], nil)
    expect_raises(ArgumentError, /constituent input bytes mismatch/) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(altered, productions, String.new(Bytes[0xff]), input)
    end
    original = productions.first
    truncated = Iyi::DiagnosticLiteralProductionSegment.new(original.production, original.start_offset,
      original.end_offset, original.raw_base64, original.delimiter_kind, original.nest,
      original.end_delimiter, original.allow_escapes, [original.witnesses.first])
    expect_raises(ArgumentError, /incomplete literal production witnesses/) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [truncated], String.new(Bytes[0xff]), input)
    end
    arg.name = "changed"
    expect_raises(ArgumentError, /decoded value mismatch/) do
      Iyi::DiagnosticLiteralInputChecks.verify_owner_field!(arg, "name", 0, input)
    end
    expect_raises(ArgumentError, /decoded value mismatch/) { checker.verify!(root) }
  end

  it "checks an element against its enclosing percent-symbol production" do
    source = "%i(alpha beta)"
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/literal_input.cr"
    parser.diagnostic_source_file = "/spec/literal_input.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    element = parser.parse.as(Iyi::ArrayLiteral).elements.first.as(Iyi::SymbolLiteral)
    literal = element.diagnostic_literal_names[{"value", 0}]
    productions = element.diagnostic_literal_productions[{"value", 0}]
    Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, productions, "alpha", input)
  end

  it "rejects noncanonical base64 padding without decoding" do
    segment = Iyi::DiagnosticLiteralSegment.new(0, 1, "YQ==")
    literal = Iyi::DiagnosticParsedLiteral.new("0" * 64, 1, "Crystal", "/x==", [segment], nil)
    expect_raises(ArgumentError, /noncanonical literal base64 padding/) { literal.decoded_bytesize }
  end
end

describe Iyi::DiagnosticParseToDefEffectSnapshot do
  it "rejects a skipped owner flag assignment" do
    reset = Iyi::ParseDefFlags.new(false, false, false, false, false)
    result = Iyi::ParseDefFlags.new(true, false, false, false, false)
    effect = Iyi::ParseToDefEffect.new(reset, reset, nil, false, result, result, 0, 1)
    capture = Iyi::DiagnosticParseToDefEffectSnapshot.new(effect)
    capture.sha256.should eq(::Crystal::Digest::SHA256.hexdigest(capture.bytes))
    altered = Iyi::ParseToDefEffect.new(reset, reset, nil, false, result, reset, 0, 1)
    expect_raises(ArgumentError, /owner flags differ/) do
      Iyi::DiagnosticParseToDefEffectSnapshot.new(altered)
    end
  end
end

describe Iyi::DiagnosticCaptureFieldRef do
  it "owns its coordinate strings and does not expose its internal identity" do
    capture_id = String.new(("a" * 64).to_slice)
    owner_path = String.new("[]".to_slice)
    field = String.new("name".to_slice)
    ref = Iyi::DiagnosticCaptureFieldRef.new(capture_id, owner_path, field)
    capture_id.to_unsafe[0] = 'b'.ord.to_u8
    owner_path.to_unsafe[0] = 'X'.ord.to_u8
    field.to_unsafe[0] = 'X'.ord.to_u8
    ref.capture_id.should eq("a" * 64)
    ref.owner_path_json.should eq("[]")
    ref.field_tag.should eq("name")
    copy = ref.capture_id
    copy.to_unsafe[0] = 'b'.ord.to_u8
    ref.capture_id.should eq("a" * 64)
  end
end
