require "../spec_helper"
require "./spec_helper"
require "../support/env"

class Iyi::SemanticVisitor
  def import_regex_fixture(artifact : Iyi::IyiMod::Artifact, path : String) : Nil
    define_iyi_artifact_regexes(artifact, path)
  end
end

private class NonPositionableDiagnosticIO < IO
  getter buffer = IO::Memory.new

  def read(slice : Bytes)
    0
  end

  def write(slice : Bytes) : Nil
    @buffer.write(slice)
  end
end

private def diagnostic_arrow_fragment(key : String, text : String, origin : Iyi::DiagnosticOrigin,
                                      mode : String = "Crystal") : Iyi::IyiMod::DiagnosticFragment
  raise ArgumentError.new("arrow fixture does not start with an arrow") unless text.starts_with?("->")
  event = Iyi::DiagnosticTokenEvent.new(0, 2, "->", "->", mode, Iyi::DiagnosticTokenSelection::Whole,
    [Iyi::DiagnosticEmissionPart::AstAnchor.new(0, 2, nil, origin)] of Iyi::DiagnosticEmissionPart)
  anchor = Iyi::DiagnosticAnchor.new(0, "ProcLiteral", "arrow", origin,
    {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue), 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
  Iyi::IyiMod::DiagnosticFragment.new(key, ::Crystal::Digest::SHA256.hexdigest(text), [event], [anchor])
end

private def captured_diagnostic_def(source : String, file : String, mode : String) : Iyi::Def
  parser = Iyi::Parser.new(source)
  parser.filename = file
  parser.diagnostic_source_file = file
  parser.iyi = mode == "Iyi"
  parser.diagnostic_capture = true
  parser.parse.as(Iyi::Def)
end

private def captured_diagnostic_macro(source : String, file : String) : Iyi::Macro
  parser = Iyi::Parser.new(source)
  parser.filename = file
  parser.diagnostic_source_file = file
  parser.diagnostic_capture = true
  parser.parse.as(Iyi::Macro)
end

private def diagnostic_macro_claim(first : Int32, last : Int32, kind : String, role : String,
                                   evidence : Iyi::DiagnosticAnchorEvidence,
                                   emitter : Iyi::DiagnosticOrigin?) : Iyi::DiagnosticMacroClaim
  writer = Iyi::DiagnosticWriterRef.new(first, last)
  key = Iyi::DiagnosticMacroClaimKey.new(writer, kind, role)
  Iyi::DiagnosticMacroClaim.new(key, evidence, Iyi::DiagnosticMacroAttachment::Direct.new(writer), emitter)
end

describe "diagnostic token input offsets" do
  it "tracks byte offsets through skipped comments and lookahead" do
    lexer = Iyi::Lexer.new("# é\n  x")
    lexer.next_token.input_offset.should eq(4)
    lexer.next_token.input_offset.should eq(5)
    lexer.peek_ahead { lexer.next_token.input_offset }.should eq(7)
    lexer.token.input_offset.should eq(5)
    lexer.next_token.input_offset.should eq(7)
    lexer.next_token.input_offset.should eq(8)
  end

  it "tracks macro and string tokens in the original byte stream" do
    macro_lexer = Iyi::Lexer.new("  hello {{world}}")
    macro_token = macro_lexer.next_macro_token(Iyi::Token::MacroState.default, true)
    macro_token.input_offset.should eq(2)
    macro_lexer.next_macro_token(macro_token.macro_state, false).input_offset.should eq(8)

    string_lexer = Iyi::Lexer.new(%("éx"))
    delimiter = string_lexer.next_token
    delimiter.input_offset.should eq(0)
    string_lexer.next_string_token(delimiter.delimiter_state).input_offset.should eq(1)
  end

  it "keeps input offsets separate from location pragmas" do
    source = %q(#<loc:"original.iyi",40,3>x)
    token = Iyi::Lexer.new(source).next_token
    token.input_offset.should eq(source.bytesize - 1)
    token.location.filename.should eq("original.iyi")
    token.location.line_number.should eq(40)
  end

  it "counts the UTF-8 BOM stripped before lexing" do
    lexer = Iyi::Lexer.new("\uFEFFx")
    lexer.next_token.input_offset.should eq(3)
    lexer.next_token.input_offset.should eq(4)
  end

  it "copies the input offset independently of the token's source location" do
    original = Iyi::Token.new
    original.input_offset = 19
    copy = Iyi::Token.new
    copy.copy_from(original)
    copy.input_offset.should eq(19)
  end
end

describe Iyi::DiagnosticOrigin do
  it "retains the complete tagged origin through cloning and at(node)" do
    call = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 8, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 3, "Macro", "keyword")
    splice = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 20, "Block", "opener")
    event = Iyi::DiagnosticTokenEvent.new(17, 18, "{", "{", "Iyi", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::AstAnchor.new(17, 18, nil, splice)] of Iyi::DiagnosticEmissionPart)
    expansion = Iyi::DiagnosticOrigin::Expanded.new(call, definition, "sha256:" + "0" * 64,
      "Block", "opener", nil, event, Iyi::DiagnosticAnchorUse::Direct.new)
    origin = Iyi::DiagnosticOrigin::Synthetic.new(expansion, "block_to_proc", "proc")
    node = Iyi::Nop.new
    node.diagnostic_origin = origin
    node.clone.diagnostic_origin.should eq(origin)
    Iyi::Nop.new.at(node).diagnostic_origin.should eq(origin)
    json = node.diagnostic_origin_json.not_nil!
    json["parent_origin"]["token_event"]["input_start"].as_i.should eq(17)
    json["parent_origin"]["token_event"]["byte_parts"][0]["source_origin"]["source_identity"]["module"].as_s.should eq("app/main")
    json["parent_origin"]["macro_definition_origin"]["input_byte_offset"].as_i.should eq(3)
    Iyi::DiagnosticOrigin.from_json(json).should eq(origin)
  end

  it "prints empty tuple projections without seeking and retains captured offsets" do
    cases = [
      {Iyi::TupleLiteral.new([] of Iyi::ASTNode), "::Tuple.new", 8, Iyi::DiagnosticMacroProducer::EmptyTupleProjection},
      {Iyi::NamedTupleLiteral.new([] of Iyi::NamedTupleLiteral::Entry), "::NamedTuple.new", 13, Iyi::DiagnosticMacroProducer::EmptyNamedTupleProjection},
    ]
    cases.each do |node, expected, method_offset, producer|
      node.to_s.should eq(expected)
      unseekable = NonPositionableDiagnosticIO.new
      node.to_s(unseekable)
      unseekable.buffer.to_s.should eq(expected)

      io = IO::Memory.new
      io << "prefix "
      emissions = [] of Iyi::DiagnosticMacroClaim
      generated = [] of Iyi::DiagnosticGeneratedText
      node.to_s(io, diagnostic_claims: emissions, diagnostic_generated_text: generated)
      io.to_s.should eq("prefix " + expected)
      emissions.should eq([diagnostic_macro_claim(7 + method_offset, 10 + method_offset, "Call", "method",
        Iyi::DiagnosticAnchorEvidence::Constructed.new(producer), nil)])
      generated.should eq([Iyi::DiagnosticGeneratedText.new(7, 7 + expected.bytesize, nil, producer)])
    end
  end

  it "captures hook trigger keywords at their written and printed byte offsets" do
    cases = [
      {"include Feature", "Include", "include"},
      {"extend Feature", "Extend", "extend"},
      {"class Child\nend", "ClassDef", "class"},
      {"struct Child\nend", "ClassDef", "struct"},
      {"abstract class Child\nend", "ClassDef", "class"},
      {"abstract struct Child\nend", "ClassDef", "struct"},
    ]
    cases.each do |source, kind, keyword|
      parser = Iyi::Parser.new(source)
      parser.filename = "/src/hooks.cr"
      parser.diagnostic_source_file = "/src/hooks.cr"
      parser.diagnostic_capture = true
      node = parser.parse
      origin = node.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
      origin.input_byte_offset.should eq(source.byte_index(keyword).not_nil!)
      origin.valid_for_anchor?(kind, "keyword").should be_true

      io = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      node.to_s(io, diagnostic_fragment: builder)
      text = io.to_s
      fragment = builder.finish("fixture", text)
      anchors = fragment.anchors
      anchor = anchors.find { |item| item.kind == kind && item.role == "keyword" }.not_nil!
      text.byte_slice(anchor.offset, keyword.bytesize).should eq(keyword)
      anchor.origin.should eq(origin)
      restored = Iyi::Parser.new(text)
      restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, anchors)]
      restored.parse.diagnostic_origin.should eq(origin)

      missing = Iyi::Parser.new(text)
      expect_raises(ArgumentError) do
        missing.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, anchors.reject { |item| item == anchor })]
        missing.parse
      end
      changed = Iyi::Parser.new(text + " ")
      expect_raises(ArgumentError) do
        changed.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize + 1, fragment.text_sha256, fragment.events, anchors)]
      end
    end
  end
  it "preserves a spliced local binding's call anchor when reparsing an assignment" do
    source = Iyi::Parser.new("evloop = 1")
    source.filename = "/src/fiber.cr"
    source.diagnostic_source_file = "/src/fiber.cr"
    source.diagnostic_capture = true
    assignment = source.parse.as(Iyi::Assign)
    binding = assignment.target.as(Iyi::Var).diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic)
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.cr", 20, "MacroDirective", "expression")
    io = IO::Memory.new
    anchors = [] of Iyi::DiagnosticMacroClaim
    generated = [] of Iyi::DiagnosticGeneratedText
    names = [] of Iyi::DiagnosticMacroNameFragment
    assignment.to_s(io, diagnostic_claims: anchors, diagnostic_generated_text: generated,
      diagnostic_name_fragments: names, diagnostic_emitter: emitter)
    name_only = IO::Memory.new
    name_anchors = [] of Iyi::DiagnosticMacroClaim
    name_fragments = [] of Iyi::DiagnosticMacroNameFragment
    assignment.target.to_s(name_only, diagnostic_claims: name_anchors,
      diagnostic_name_fragments: name_fragments, diagnostic_emitter: emitter)
    name_only.to_s.should eq("evloop")
    name_anchors.should be_empty
    name_fragments.size.should eq(1)
    name_fragments.first.source_name.as(Iyi::DiagnosticNameValue::Observed).source_token.lexical_origin.should eq(binding.parent_origin)
    name_fragments.first.source_name.as(Iyi::DiagnosticNameValue::Observed).source_token.binding_origin.should eq(binding)
    text = io.to_s
    names.first.source_name.should eq(name_fragments.first.source_name)
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 1, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.cr", 1, "Macro", "keyword")
    emission = Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, anchors, generated, names)
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}",
      {0 => [emission] of Iyi::Lexer::LocPragma})
    restored = parser.parse.as(Iyi::Assign).target.as(Iyi::Var).diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic)
    expanded = restored.parent_origin.as(Iyi::DiagnosticOrigin::Expanded)
    expanded.token_event.byte_parts.first.as(Iyi::DiagnosticEmissionPart::NameSplice).source_name.as(Iyi::DiagnosticNameValue::Observed).source_token.lexical_origin.should eq(binding.parent_origin)
    expanded.token_event.byte_parts.first.emitter_origin.should eq(emitter)
    parser.diagnostic_check_consumed

    missing = Iyi::Parser.new(text)
    missing.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}",
      {0 => [Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, [] of Iyi::DiagnosticMacroClaim, generated, [] of Iyi::DiagnosticMacroNameFragment)] of Iyi::Lexer::LocPragma})
    expect_raises(ArgumentError) { missing.parse }
  end

  it "round trips expansions rooted in real hook trigger tokens and rejects other ancestry" do
    macro_parser = Iyi::Parser.new("macro included\n  def generated\n    -> { 1 }\n  end\nend")
    macro_parser.filename = "/src/hooks.cr"
    macro_parser.diagnostic_source_file = "/src/hooks.cr"
    macro_parser.diagnostic_capture = true
    macro_node = macro_parser.parse.as(Iyi::Macro)
    definition = macro_node.diagnostic_origin.not_nil!
    program = Iyi::Program.new
    program.diagnostic_capture = true
    text, pragmas = program.expand_macro(macro_node.body, program, program)
    cases = [
      {"include Feature", "Include"},
      {"extend Feature", "Extend"},
      {"class Child\nend", "ClassDef"},
      {"def method\nend", "Def"},
      {"macro finished\nend", "Macro"},
    ]
    cases.each do |source, kind|
      trigger_parser = Iyi::Parser.new(source)
      trigger_parser.filename = "/src/main.cr"
      trigger_parser.diagnostic_source_file = "/src/main.cr"
      trigger_parser.diagnostic_capture = true
      trigger = trigger_parser.parse.diagnostic_origin.not_nil!
      trigger.valid_for_anchor?(kind, "keyword").should be_true
      parser = Iyi::Parser.new(text)
      parser.diagnostic_expansion(trigger, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", pragmas)
      generated_def = parser.parse.as(Iyi::Def)
      generated_def.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded).invocation_origin.should eq(trigger)
      origin = generated_def.body.as(Iyi::ProcLiteral).diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
      origin.invocation_origin.should eq(trigger)
      origin.macro_definition_origin.should eq(definition)
      Iyi::DiagnosticOrigin.from_json(origin.as_json).should eq(origin)
      table = Iyi::IyiMod::DiagnosticOrigins.new
      index = table.intern(origin)
      io = IO::Memory.new
      table.write(io)
      io.rewind
      Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).should eq(origin)
    end

    parts = [Iyi::DiagnosticEmissionPart::Generated.new(0, 2, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart
    event = Iyi::DiagnosticTokenEvent.new(0, 2, "->", "->", "Iyi", Iyi::DiagnosticTokenSelection::Whole, parts)
    [{"Include", "method"}, {"Extend", "control"}, {"ClassDef", "method"},
     {"Def", "method"}, {"Macro", "control"}, {"Module", "keyword"}].each do |kind, role|
      invalid = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 0, kind, role)
      expect_raises(ArgumentError) do
        Iyi::DiagnosticOrigin::Expanded.new(invalid, definition, "sha256:" + "0" * 64, "ProcLiteral", "arrow", nil, event, Iyi::DiagnosticAnchorUse::Direct.new)
      end
    end
    valid = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 0, "Include", "keyword")
    wrong_definition = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.cr", 1, "Def", "keyword")
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::Expanded.new(valid, wrong_definition, "sha256:" + "0" * 64, "ProcLiteral", "arrow", nil, event, Iyi::DiagnosticAnchorUse::Direct.new)
    end
  end


  it "records the printed proc arrow at its exact byte offset" do
    origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 7, "ProcLiteral", "arrow")
    literal = Iyi::ProcLiteral.new
    literal.diagnostic_origin = origin
    io = IO::Memory.new
    io << "prefix "
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    literal.accept Iyi::ToSVisitor.new(io, diagnostic_fragment: builder)
    anchor = builder.finish("fixture", io.to_s).anchors.find { |item| item.kind == "ProcLiteral" }.not_nil!
    anchor.offset.should eq(7)
    anchor.role.should eq("arrow")
    anchor.origin.should eq(origin)
    io.to_s.byte_slice(anchor.offset, 2).should eq("->")
  end

  it "carries an operator invocation at the operator token" do
    parser = Iyi::Parser.new("1 + 2")
    parser.filename = "/src/math.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/math.cr"
    call = parser.parse.as(Iyi::Call)
    origin = call.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
    origin.input_byte_offset.should eq(2)
    io = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    call.to_s(io, diagnostic_fragment: builder)
    text = io.to_s
    fragment = builder.finish("fixture", text)
    anchors = fragment.anchors
    anchors.size.should eq(1)
    text.byte_slice(anchors.first.offset, 1).should eq("+")
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, anchors)]
    restored.parse.as(Iyi::Call).diagnostic_origin.should eq(origin)
  end

  it "derives a compound operator call from its written assignment token" do
    parser = Iyi::Parser.new("@x += 1")
    parser.filename = "/src/math.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/math.cr"
    assignment = parser.parse.as(Iyi::OpAssign)
    origin = assignment.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
    origin.input_byte_offset.should eq(3)
    io = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    assignment.to_s(io, diagnostic_fragment: builder)
    text = io.to_s
    fragment = builder.finish("fixture", text)
    restored = Iyi::Parser.new(text)
    restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    restored.parse.as(Iyi::OpAssign).diagnostic_origin.should eq(origin)
    lowered = Iyi::Program.new.normalize(assignment).as(Iyi::Assign)
    lowered.value.as(Iyi::Call).diagnostic_origin.should eq(origin)
  end

  it "scans field mutation through an inline macro with diagnostic capture" do
    source = <<-CRYSTAL
      class Probe
        def bump
          {% if true %}
            @count = 1
          {% end %}
        end
      end
      CRYSTAL
    parser = Iyi::Parser.new(source)
    parser.filename = "/src/probe.cr"
    parser.diagnostic_source_file = "/src/probe.cr"
    parser.diagnostic_capture = true
    definition = parser.parse.as(Iyi::ClassDef).body.as(Iyi::Def)
    program = Iyi::Program.new
    program.diagnostic_capture = true
    scanner = Iyi::Share::MutationScanner.new(program, program, definition)
    definition.body.accept(scanner)
    scanner.unexpanded?.should be_false
    scanner.fields.should contain("@count")
  end

  it "retains every interned regex occurrence and the actual initializer origin" do
    program = Iyi::Program.new
    program.diagnostic_capture = true
    expander = Iyi::LiteralExpander.new(program)
    location = Iyi::Location.new("/src/literals.cr", 10, 4)
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/literals.cr", 20, "Call", "method")
    macro_origin = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.cr", 2, "Macro", "keyword")
    origins = [
      Iyi::DiagnosticOrigin::Written.new("app/main", "/src/literals.cr", 4, "Literal", "regex"),
      Iyi::DiagnosticOrigin::Expanded.new(invocation, macro_origin, "sha256:" + "0" * 64, "Literal", "regex", nil,
        Iyi::DiagnosticTokenEvent.new(8, 9, "DELIMITER_START", "/", "Iyi", Iyi::DiagnosticTokenSelection::Whole,
          [Iyi::DiagnosticEmissionPart::Generated.new(8, 9, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart),
        Iyi::DiagnosticAnchorUse::Direct.new),
    ] of Iyi::DiagnosticOrigin
    references = origins.map do |origin|
      literal = Iyi::RegexLiteral.new(Iyi::StringLiteral.new("same")).at(location)
      literal.diagnostic_origin = origin
      expander.expand(literal).as(Iyi::Path)
    end
    references.map(&.diagnostic_origin).should eq(origins)
    repeated = Iyi::RegexLiteral.new(Iyi::StringLiteral.new("same")).at(location)
    repeated.diagnostic_origin = origins.first
    expander.expand(repeated).as(Iyi::Path).diagnostic_origin.should eq(origins.first)
    name = Iyi::Program.regex_const_name("same", Iyi::RegexOptions::None)
    diagnostic = program.diagnostic_regex_record(name)
    diagnostic.initializer_origin.should eq(origins.first)
    diagnostic.literal_origins.should eq(origins.sort_by(&.to_json))
    factory = program.types[name].as(Iyi::Const).value.as(Iyi::Call)
    factory.diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origins.first)
    flags = factory.args.last.as(Iyi::Call)
    flags.diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origins.first)
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_regex(diagnostic)
    expect_raises(ArgumentError) { section.add_regex(diagnostic) }
    invalid = Iyi::IyiMod::DiagnosticRegex.new(name, "other", 0_u32, origins.first, [origins.first])
    expect_raises(ArgumentError) { Iyi::IyiMod::DiagnosticSection.new.add_regex(invalid) }
    reversed = Iyi::IyiMod::DiagnosticRegex.new(name, "same", 0_u32, origins.first, diagnostic.literal_origins.reverse)
    expect_raises(ArgumentError) { Iyi::IyiMod::DiagnosticSection.new.add_regex(reversed) }
    wire = section.encode
    expect_raises(Exception) { Iyi::IyiMod::DiagnosticSection.decode(wire[0, wire.size - 1]) }
    artifact = sample_artifact
    artifact.regexes << Iyi::IyiMod::RegexConst.new(name, "same", 0_u32)
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      restored = Iyi::IyiMod.read(path)
      restored.diagnostic_provenance.not_nil!.regexes[name].should eq(diagnostic)
      consumer = Iyi::Program.new
      consumer.diagnostic_capture = true
      visitor = Iyi::TopLevelVisitor.new(consumer)
      visitor.import_regex_fixture(restored, "/absent/first.iyimod")
      selected = consumer.types[name].as(Iyi::Const)
      selected.value.as(Iyi::Call).diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origins.first)
      second_section = Iyi::IyiMod::DiagnosticSection.new
      second_section.add_regex(Iyi::IyiMod::DiagnosticRegex.new(name, "same", 0_u32, origins.last, [origins.last]))
      second = sample_artifact
      second.regexes << Iyi::IyiMod::RegexConst.new(name, "same", 0_u32)
      second.diagnostic_provenance = second_section
      visitor.import_regex_fixture(second, "/absent/second.iyimod")
      consumer.types[name].same?(selected).should be_true
      merged = consumer.diagnostic_regex_record(name)
      merged.initializer_origin.should eq(origins.first)
      merged.literal_origins.should eq(origins.sort_by(&.to_json))
      other_name = Iyi::Program.regex_const_name("different", Iyi::RegexOptions::None)
      expect_raises(Exception, /conflicting/) do
        consumer.record_regex_occurrence(other_name, "different", 0_u32, origins.first)
      end
      other_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/literals.cr", 80, "Literal", "regex")
      expect_raises(Exception, /conflicting/) do
        consumer.record_regex_occurrence(name, "different", 0_u32, other_origin)
      end
      consumer.diagnostic_regex_origin_tuples.has_key?(other_origin).should be_false
      reemitted = sample_artifact
      reemitted.regexes << Iyi::IyiMod::RegexConst.new(name, "same", 0_u32)
      reemitted_section = Iyi::IyiMod::DiagnosticSection.new
      reemitted_section.add_regex(merged)
      reemitted.diagnostic_provenance = reemitted_section
      first_hashes = Iyi::IyiMod.hashes_for(restored, "unchanged source")
      second_hashes = Iyi::IyiMod.hashes_for(reemitted, "unchanged source")
      first_hashes.should eq(second_hashes)
      Iyi::IyiMod.write reemitted, path
      Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.regexes[name].should eq(merged)
      restored.diagnostic_provenance.not_nil!.regexes.clear
      expect_raises(ArgumentError) { Iyi::IyiMod.write restored, path }
    end
  end

  it "attributes native regex factory calls to the recorded initializer" do
    origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 3, "Literal", "regex")
    location = Iyi::Location.new("/absent/app.iyimod", 1, 1)
    plain = Iyi::Program.iyi_regex_compile_call(Iyi::StringLiteral.new("x"), Iyi::RegexOptions::None, location,
      diagnostic_literal_origin: origin)
    plain.args.size.should eq(1)
    plain.diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origin)
    flagged = Iyi::Program.iyi_regex_compile_call(Iyi::StringLiteral.new("x"), Iyi::RegexOptions::IGNORE_CASE, location,
      diagnostic_literal_origin: origin)
    flagged.args.size.should eq(2)
    flagged.diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origin)
    flagged.args.last.as(Iyi::Call).diagnostic_origin.as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origin)
  end

  it "distinguishes structured group lowering slots" do
    parent = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    first = Iyi::DiagnosticOrigin::Synthetic.new(parent, "group_lowering", "value:0")
    second = Iyi::DiagnosticOrigin::Synthetic.new(parent, "group_lowering", "value:1")
    malformed = Iyi::DiagnosticOrigin::Synthetic.new(parent, "group_lowering", "value:01")
    first.valid_for_anchor?("Call", "method").should be_true
    second.valid_for_anchor?("Call", "method").should be_true
    first.should_not eq(second)
    malformed.valid_for_anchor?("Call", "method").should be_false
  end

  it "keeps synthetic literal calls distinct at identical displayed locations" do
    program = Iyi::Program.new
    program.diagnostic_capture = true
    expander = Iyi::LiteralExpander.new(program)
    location = Iyi::Location.new("/src/main.iyi", 10, 4)
    origins = [
      Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 20, "Literal", "array"),
      Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 30, "Literal", "array"),
    ]
    calls = origins.map do |origin|
      literal = Iyi::ArrayLiteral.new([Iyi::NumberLiteral.new(1)] of Iyi::ASTNode).at(location)
      literal.diagnostic_origin = origin
      expansion = expander.expand(literal).as(Iyi::Expressions)
      constructor = expansion.expressions.first.as(Iyi::Assign).value.as(Iyi::Call)
      buffer = expansion.expressions[1].as(Iyi::Assign).value.as(Iyi::Call)
      store = expansion.expressions[2].as(Iyi::Call)
      constructor.diagnostic_origin.should_not eq(buffer.diagnostic_origin)
      constructor.diagnostic_origin.should_not eq(store.diagnostic_origin)
      buffer.diagnostic_origin.should_not eq(store.diagnostic_origin)
      constructor.diagnostic_origin.not_nil!
    end
    calls[0].should_not eq(calls[1])
    calls.each { |origin| origin.valid_for_anchor?("Call", "method").should be_true }
    calls[0].as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origins[0])
    calls[1].as(Iyi::DiagnosticOrigin::Synthetic).parent_origin.should eq(origins[1])
  end

  it "distinguishes range and interpolation calls at one displayed location" do
    program = Iyi::Program.new
    program.diagnostic_capture = true
    expander = Iyi::LiteralExpander.new(program)
    location = Iyi::Location.new("/src/main.iyi", 10, 4)
    range = Iyi::RangeLiteral.new(Iyi::NumberLiteral.new(1), Iyi::NumberLiteral.new(2), false).at(location)
    range.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 20, "Literal", "range")
    interpolation = Iyi::StringInterpolation.new([Iyi::StringLiteral.new("x"), Iyi::NumberLiteral.new(2)] of Iyi::ASTNode).at(location)
    interpolation.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 30, "Literal", "interpolation")
    range_origin = expander.expand(range).as(Iyi::Call).diagnostic_origin.not_nil!
    interpolation_origin = expander.expand(interpolation).as(Iyi::Call).diagnostic_origin.not_nil!
    range_origin.valid_for_anchor?("Call", "method").should be_true
    interpolation_origin.valid_for_anchor?("Call", "method").should be_true
    range_origin.should_not eq(interpolation_origin)
  end

  it "separates hash construction and entry stores at the same location" do
    program = Iyi::Program.new
    program.diagnostic_capture = true
    parent = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 14, "Literal", "hash")
    entries = [Iyi::HashLiteral::Entry.new(Iyi::NumberLiteral.new(1), Iyi::NumberLiteral.new(2))]
    literal = Iyi::HashLiteral.new(entries).at(Iyi::Location.new("/src/main.iyi", 10, 4))
    literal.diagnostic_origin = parent
    expressions = Iyi::LiteralExpander.new(program).expand(literal).as(Iyi::Expressions).expressions
    constructor = expressions[0].as(Iyi::Assign).value.as(Iyi::Call).diagnostic_origin.not_nil!
    store = expressions[1].as(Iyi::Call).diagnostic_origin.not_nil!
    constructor.should_not eq(store)
    constructor.valid_for_anchor?("Call", "method").should be_true
    store.valid_for_anchor?("Call", "method").should be_true
  end

  it "restores source anchors for carried literal forms" do
    cases = [
      {"[1]", "array"},
      {"{1 => 2}", "hash"},
      {"1..2", "range"},
      {"/abc/", "regex"},
      { %q("value #{1}"), "interpolation" },
      {"case 1\nwhen 1\n2\nend", "case"},
      {"a, b = 1, 2", "multiassign"},
      {"select\nwhen channel.receive\n1\nend", "select"},
    ]
    cases.each do |source, role|
      parser = Iyi::Parser.new(source)
      parser.filename = "/src/literals.cr"
      parser.diagnostic_capture = true
      parser.diagnostic_source_file = "/src/literals.cr"
      node = parser.parse
      origin = node.diagnostic_origin.not_nil!
      origin.valid_for_anchor?("Literal", role).should be_true
      text, _, builder = Iyi::IyiMod.diagnostic_located_source(node, "Crystal")
      fragment = builder.finish("literal", text)
      anchors = fragment.anchors
      if role == "multiassign"
        anchors.any? { |anchor| anchor.offset == 0 && anchor.kind == "Call" && anchor.role == "method" }.should be_true
      end
      restored = Iyi::Parser.new(text)
      restored.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize,
        fragment.text_sha256, fragment.events, anchors)]
      restored.parse.diagnostic_origin.should eq(origin)
    end
  end

  it "records a shorthand block even though the printer bypasses its visitor" do
    block_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 12, "Block", "ampersand")
    inner = Iyi::Call.new(Iyi::Var.new("__arg0"), "foo")
    block = Iyi::Block.new([Iyi::Var.new("__arg0")], inner)
    block.diagnostic_origin = block_origin
    call = Iyi::Call.new(nil, "map", [] of Iyi::ASTNode, block)
    io = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    call.accept Iyi::ToSVisitor.new(io, diagnostic_fragment: builder)
    anchor = builder.finish("fixture", io.to_s).anchors.find { |item| item.kind == "Block" }.not_nil!
    anchor.role.should eq("ampersand")
    anchor.origin.should eq(block_origin)
    io.to_s.byte_slice(anchor.offset, 2).should eq("&.")
  end

  it "restores a guarded parser anchor and rejects changed or incomplete text" do
    text = "-> { 1 }"
    origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 41, "ProcLiteral", "arrow")
    fragment = diagnostic_arrow_fragment("body:f", text, origin)
    anchor = fragment.anchors.first
    digest = fragment.text_sha256
    region = Iyi::DiagnosticRegion.new(0, text.bytesize, digest, fragment.events, [anchor])
    parser = Iyi::Parser.new(text)
    parser.diagnostic_regions = [region]
    parser.parse.diagnostic_origin.should eq(origin)

    changed = Iyi::Parser.new("-> { 2 }")
    expect_raises(ArgumentError) { changed.diagnostic_regions = [region] }
    missing = Iyi::Parser.new(text)
    expect_raises(ArgumentError) do
      missing.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, digest, fragment.events, [] of Iyi::DiagnosticAnchor)]
      missing.parse
    end

    duplicate = Iyi::Parser.new(text)
    expect_raises(ArgumentError) do
      duplicate.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, digest, fragment.events, [anchor, anchor])]
    end
    wrong_offset = Iyi::Parser.new(text)
    bad_anchor = anchor.copy_with(offset: 1)
    expect_raises(ArgumentError) do
      wrong_offset.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, text.bytesize, digest, fragment.events, [bad_anchor])]
      wrong_offset.parse
    end
  end

  it "maps anchored bytes through indented artifact body rendering" do
    text = "-> do\n  1\nend"
    origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 41, "ProcLiteral", "arrow")
    fragment = diagnostic_arrow_fragment("body:f", text, origin)
    io = IO::Memory.new
    bodies = Iyi::IyiMod::Bodies.new(sample_artifact)
    region = bodies.write_diagnostic(io, text, [] of Iyi::IyiMod::SourcePosition, fragment, "  ")
    parser = Iyi::Parser.new(io.to_s)
    parser.diagnostic_regions = [region]
    parser.parse.diagnostic_origin.should eq(origin)
  end

  it "restores a carried mono body at its exact rendered anchor" do
    original_def = captured_diagnostic_def("def f\nend", "/absent/greeter.iyi", "Iyi")
    sig = signature("f")
    sig.diagnostic_origin = original_def.diagnostic_origin
    artifact = sample_artifact(exports: [sig])
    key = Iyi::IyiMod.mono_body_key(artifact.module_name, sig)
    text = "-> { 1 }"
    artifact.mono_bodies[key] = text
    origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 15, "ProcLiteral", "arrow")
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(Iyi::IyiMod.diagnostic_signature_fragment(artifact.module_name, original_def, sig, "Iyi"))
    section.add_fragment(diagnostic_arrow_fragment(Iyi::IyiMod.signature_body_fragment_key(artifact.module_name, sig), text, origin, "Iyi"))
    artifact.diagnostic_provenance = section
    io = IO::Memory.new
    pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
    regions = [] of Iyi::DiagnosticRegion
    Iyi::IyiMod.declarations(artifact, io, pragmas, "greeter.iyimod", regions)
    parser = Iyi::Parser.new(io.to_s)
    parser.filename = "greeter.iyimod"
    parser.artifact = "greeter.iyimod"
    parser.iyi = true
    parser.diagnostic_regions = regions
    parser.parse
    regions.size.should eq(2)
    regions.last.anchors.first.origin.should eq(origin)
  end

  it "restores a definition and a closure in its parameter default" do
    definition = captured_diagnostic_def("def f(x = -> { 1 })\nend", "/absent/greeter.cr", "Crystal")
    def_origin = definition.diagnostic_origin.not_nil!
    proc_origin = definition.args.first.default_value.not_nil!.diagnostic_origin.not_nil!
    sig = Iyi::IyiMod.signature(definition, check_block: false)
    fragment = Iyi::IyiMod.diagnostic_signature_fragment("app/greeter", definition, sig, "Crystal")
    header = Iyi::IyiMod.render_signature(sig)
    region = Iyi::DiagnosticRegion.new(0, header.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)
    parser = Iyi::Parser.new("#{header}\nend")
    parser.diagnostic_regions = [region]
    restored = parser.parse.as(Iyi::Def)
    restored.diagnostic_origin.should eq(def_origin)
    restored.args.first.default_value.not_nil!.diagnostic_origin.should eq(proc_origin)
  end

  it "round-trips same-header definitions and their distinct closure origins without source" do
    definition_source = "def f(x : Proc(Int32) = -> { 1 }) : Proc(Int32)\nend"
    first = captured_diagnostic_def(definition_source, "/absent/first.iyi", "Iyi")
    second = captured_diagnostic_def(definition_source, "/absent/second.iyi", "Iyi")
    defaults = [first, second].map { |definition| definition.args.first.default_value.not_nil!.diagnostic_origin.not_nil! }
    signatures = [Iyi::IyiMod.signature(first), Iyi::IyiMod.signature(second)]
    artifact = sample_artifact(exports: signatures)
    section = Iyi::IyiMod::DiagnosticSection.new
    closures = [
      Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 12, "ProcLiteral", "arrow"),
      Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 48, "ProcLiteral", "arrow"),
    ]
    [first, second].each_with_index do |definition, index|
      sig = signatures[index]
      text = "-> { #{index + 1} }"
      artifact.mono_bodies[Iyi::IyiMod.mono_body_key(artifact.module_name, sig, index)] = text
      section.add_fragment(Iyi::IyiMod.diagnostic_signature_fragment(artifact.module_name, definition, sig, "Iyi"))
      section.add_fragment(diagnostic_arrow_fragment(Iyi::IyiMod.signature_body_fragment_key(artifact.module_name, sig), text, closures[index], "Iyi"))
    end
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      restored = Iyi::IyiMod.read(path)
      restored.exports.functions.map(&.diagnostic_origin).should eq([first.diagnostic_origin, second.diagnostic_origin])
      io = IO::Memory.new
      pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
      regions = [] of Iyi::DiagnosticRegion
      Iyi::IyiMod.declarations(restored, io, pragmas, path, regions)
      parser = Iyi::Parser.new(io.to_s)
      parser.iyi = true
      parser.diagnostic_regions = regions
      parsed = parser.parse.as(Iyi::Expressions)
      module_node = parsed.expressions.last.as(Iyi::ModuleDef)
      definitions = module_node.body.as(Iyi::Expressions).expressions.compact_map(&.as?(Iyi::Def))
      definitions.size.should eq(2)
      definitions.map(&.diagnostic_origin).should eq([first.diagnostic_origin, second.diagnostic_origin])
      definitions.map { |definition| definition.args.first.default_value.not_nil!.diagnostic_origin }.should eq(defaults)
      definitions.map { |definition| definition.body.as(Iyi::ProcLiteral).diagnostic_origin }.should eq(closures)
      emitted_signatures = definitions.map { |definition| Iyi::IyiMod.signature(definition) }
      reemitted = sample_artifact(exports: emitted_signatures)
      reemitted_section = Iyi::IyiMod::DiagnosticSection.new
      definitions.each_with_index do |definition, index|
        sig = emitted_signatures[index]
        text, positions, builder = Iyi::IyiMod.diagnostic_located_source(definition.body, "Iyi")
        body_key = Iyi::IyiMod.mono_body_key(reemitted.module_name, sig, index)
        reemitted.mono_bodies[body_key] = text
        reemitted.body_positions[body_key] = positions
        reemitted_section.add_fragment(Iyi::IyiMod.diagnostic_signature_fragment(reemitted.module_name, definition, sig, "Iyi"))
        reemitted_section.add_fragment(builder.finish(Iyi::IyiMod.signature_body_fragment_key(reemitted.module_name, sig), text))
      end
      reemitted.diagnostic_provenance = reemitted_section
      Iyi::IyiMod.write reemitted, path
      reread = Iyi::IyiMod.read(path)
      reread.exports.functions.map(&.diagnostic_origin).should eq([first.diagnostic_origin, second.diagnostic_origin])
      reread.exports.functions.each_with_index do |sig, index|
        fragment = reread.diagnostic_provenance.not_nil!.fragments[Iyi::IyiMod.signature_body_fragment_key(reread.module_name, sig)]
        fragment.anchors.find { |anchor| anchor.kind == "ProcLiteral" }.not_nil!.origin.should eq(closures[index])
      end
      restored.exports.functions.reverse!
      expect_raises(ArgumentError) { Iyi::IyiMod.write restored, path }
    end
  end

  it "restores class-variable initializer anchors without the source file" do
    artifact = sample_artifact
    text = "-> { 1 }"
    name = "@@factory"
    artifact.exports.class_vars << Iyi::IyiMod::ClassVarDecl.new(name, "Proc(Int32)", text)
    origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 22, "ProcLiteral", "arrow")
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(diagnostic_arrow_fragment(Iyi::IyiMod.class_var_fragment_key(Iyi::IyiMod::DIAGNOSTIC_ROOT_CONTAINER, name), text, origin, "Iyi"))
    artifact.diagnostic_provenance = section
    io = IO::Memory.new
    pragmas = {} of Int32 => Array(Iyi::Lexer::LocPragma)
    regions = [] of Iyi::DiagnosticRegion
    Iyi::IyiMod.declarations(artifact, io, pragmas, "greeter.iyimod", regions)
    parser = Iyi::Parser.new(io.to_s)
    parser.filename = "greeter.iyimod"
    parser.artifact = "greeter.iyimod"
    parser.iyi = true
    parser.diagnostic_regions = regions
    parser.parse
    regions.size.should eq(1)
    regions.first.anchors.first.origin.should eq(origin)
  end

  it "restores a field initializer closure from the artifact" do
    text = "-> { 1 }"
    origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 25, "ProcLiteral", "arrow")
    declaration = type_declaration("Box", "class", fields: [{"@factory", "Proc(Int32)", text}])
    artifact = sample_artifact(types: [declaration])
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(diagnostic_arrow_fragment(Iyi::IyiMod.field_fragment_key("Box", "@factory"), text, origin, "Iyi"))
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      restored = Iyi::IyiMod.read(path)
      io = IO::Memory.new
      regions = [] of Iyi::DiagnosticRegion
      Iyi::IyiMod.declarations(restored, io, {} of Int32 => Array(Iyi::Lexer::LocPragma), path, regions)
      parser = Iyi::Parser.new(io.to_s)
      parser.iyi = true
      parser.diagnostic_regions = regions
      parser.parse
      regions.first.anchors.first.origin.should eq(origin)
      restored.diagnostic_provenance.not_nil!.fragments.delete(Iyi::IyiMod.field_fragment_key("Box", "@factory"))
      expect_raises(ArgumentError) { Iyi::IyiMod.write restored, path }
    end
  end

  it "maps macro anchors across the bound-shard public marker" do
    macro_node = captured_diagnostic_macro("macro example\nend", "/absent/greeter.cr")
    macro_node.doc = "é documentation"
    origin = macro_node.diagnostic_origin.not_nil!
    source, captures = Iyi::IyiMod.diagnostic_macro_source_modes(macro_node)
    artifact = sample_artifact
    artifact.crystal_library = true
    artifact.macro_bodies << source
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(captures.fragment(Iyi::IyiMod.macro_fragment_key(Iyi::IyiMod::DIAGNOSTIC_ROOT_CONTAINER, source), "Iyi"))
    artifact.diagnostic_provenance = section
    io = IO::Memory.new
    regions = [] of Iyi::DiagnosticRegion
    Iyi::IyiMod.declarations(artifact, io, {} of Int32 => Array(Iyi::Lexer::LocPragma), "greeter.iyimod", regions)
    parser = Iyi::Parser.new(io.to_s)
    parser.filename = "greeter.iyimod"
    parser.artifact = "greeter.iyimod"
    parser.iyi = true
    parser.diagnostic_regions = regions
    parser.parse
    regions.first.anchors.first.origin.should eq(origin)
  end

  it "distinguishes equal class-variable text in different owners" do
    program = Iyi::Program.new
    anchors = [] of Iyi::DiagnosticAnchor
    program.record_class_var_diagnostic("A", "@@x", "1", anchors)
    program.record_class_var_diagnostic("B", "@@x", "1", anchors)
    program.iyi_class_var_diagnostics.size.should eq(2)
    Iyi::IyiMod.class_var_fragment_key("A", "@@x").should_not eq(Iyi::IyiMod.class_var_fragment_key("B", "@@x"))
    expect_raises(Exception) { program.record_class_var_diagnostic("A", "@@x", "2", anchors) }
  end

  it "distinguishes equal macro text in different owners" do
    program = Iyi::Program.new
    anchors = [] of Iyi::DiagnosticAnchor
    source = "macro example\nend"
    program.record_macro_diagnostic("A", source, anchors)
    program.record_macro_diagnostic("B", source, anchors)
    program.iyi_macro_diagnostics.size.should eq(2)
    Iyi::IyiMod.macro_fragment_key("A", source).should_not eq(Iyi::IyiMod.macro_fragment_key("B", source))
  end

  it "restores equal macro and class-variable text in distinct type owners" do
    a = type_declaration("A", "class")
    b = type_declaration("B", "class")
    artifact = sample_artifact(types: [a, b])
    section = Iyi::IyiMod::DiagnosticSection.new
    expected = [] of Iyi::DiagnosticOrigin
    [a, b].each_with_index do |decl, index|
      proc_origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/absent/greeter.iyi", 20 + index, "ProcLiteral", "arrow")
      text = "-> { 1 }"
      decl.class_vars << Iyi::IyiMod::ClassVarDecl.new("@@x", "Proc(Int32)", text)
      section.add_fragment(diagnostic_arrow_fragment(Iyi::IyiMod.class_var_fragment_key(decl.name, "@@x"), text, proc_origin, "Iyi"))
      macro_node = captured_diagnostic_macro("macro same\nend", "/absent/macro#{index}.cr")
      macro_origin = macro_node.diagnostic_origin.not_nil!
      source, captures = Iyi::IyiMod.diagnostic_macro_source_modes(macro_node)
      decl.macros << source
      section.add_fragment(captures.fragment(Iyi::IyiMod.macro_fragment_key(decl.name, source), "Iyi"))
      expected << macro_origin << proc_origin
    end
    artifact.diagnostic_provenance = section
    io = IO::Memory.new
    regions = [] of Iyi::DiagnosticRegion
    Iyi::IyiMod.declarations(artifact, io, {} of Int32 => Array(Iyi::Lexer::LocPragma), "greeter.iyimod", regions)
    parser = Iyi::Parser.new(io.to_s)
    parser.filename = "greeter.iyimod"
    parser.artifact = "greeter.iyimod"
    parser.iyi = true
    parser.diagnostic_regions = regions
    parser.parse
    regions.flat_map(&.anchors).map(&.origin).should eq(expected)
  end

  it "derives accessor origins from the actual constant declaration" do
    parser = Iyi::Parser.new("VALUE = 1")
    parser.filename = "/src/constants.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/constants.cr"
    assignment = parser.parse.as(Iyi::Assign)
    origin = assignment.diagnostic_origin.not_nil!
    origin.valid_for_anchor?("Assign", "constant").should be_true
    accessor = Iyi::DiagnosticOrigin::Synthetic.new(origin, "constant_accessor", "getter")
    accessor.valid_for_anchor?("Def", "keyword").should be_true
    wrong = Iyi::DiagnosticOrigin::Synthetic.new(origin, "constant_accessor", "other")
    wrong.valid_for_anchor?("Def", "keyword").should be_false
    text = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    assignment.to_s(text, diagnostic_fragment: builder)
    source = text.to_s
    fragment = builder.finish("fixture", source)
    region = Iyi::DiagnosticRegion.new(0, source.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)
    restored_parser = Iyi::Parser.new(source)
    restored_parser.diagnostic_regions = [region]
    restored_parser.parse.as(Iyi::Assign).diagnostic_origin.should eq(origin)
  end

  it "restores typed global constant origins at the leading scope token" do
    parser = Iyi::Parser.new("::VALUE : Int32 = 1")
    parser.filename = "/src/constants.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/constants.cr"
    declaration = parser.parse.as(Iyi::TypeDeclaration)
    origin = declaration.diagnostic_origin.not_nil!
    origin.as(Iyi::DiagnosticOrigin::Written).input_byte_offset.should eq(0)
    text = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    declaration.to_s(text, diagnostic_fragment: builder)
    source = text.to_s
    fragment = builder.finish("fixture", source)
    parser = Iyi::Parser.new(source)
    parser.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, source.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
    parser.parse.as(Iyi::TypeDeclaration).diagnostic_origin.should eq(origin)
  end

  it "rejects source capture without a stable parser input identity" do
    parser = Iyi::Parser.new("-> { 1 }")
    parser.diagnostic_capture = true
    expect_raises(ArgumentError, /stable file identity/) { parser.parse }
  end

  it "captures the parser input file rather than a location pragma" do
    source = %(module app/main\n#<loc:"elsewhere.iyi",40,3>def f\n  -> { 1 }\nend)
    parser = Iyi::Parser.new(source)
    parser.filename = "/src/main.iyi"
    parser.diagnostic_source_file = "/src/main.iyi"
    parser.diagnostic_capture = true
    nodes = parser.parse.as(Iyi::Expressions)
    mod = nodes.expressions.last.as(Iyi::ModuleDef)
    definition = mod.body.as(Iyi::Expressions).expressions.last.as(Iyi::Def)
    literal = definition.body.as(Iyi::ProcLiteral)
    origin = literal.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
    origin.source_file.should eq("/src/main.iyi")
    origin.source_module.should eq("app/main")
    origin.input_byte_offset.should eq(source.byte_index("->").not_nil!)
  end

  it "gives a module-less Crystal file its own explicit source-unit identity" do
    parser = Iyi::Parser.new("-> { 1 }")
    parser.filename = "/src/library.cr"
    parser.diagnostic_capture = true
    parser.diagnostic_source_file = "/src/library.cr"
    origin = parser.parse.diagnostic_origin.as(Iyi::DiagnosticOrigin::Written)
    origin.source_module.should eq("source-file:/src/library.cr")
    origin.source_file.should eq("/src/library.cr")
    origin.input_byte_offset.should eq(0)
    expect_raises(ArgumentError) { parser.diagnostic_source_file = "/other.cr" }
  end

  it "retains a splice origin within the expansion occurrence" do
    text = "-> { 1 }"
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 9, "Macro", "keyword")
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 20, "MacroDirective", "expression")
    original = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 35, "ProcLiteral", "arrow")
    anchor = diagnostic_macro_claim(0, 2, "ProcLiteral", "arrow", Iyi::DiagnosticAnchorEvidence::Spliced.new(original), emitter)
    emission = Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, [anchor], [] of Iyi::DiagnosticGeneratedText, [] of Iyi::DiagnosticMacroNameFragment)
    pragmas = {0 => [emission] of Iyi::Lexer::LocPragma}
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", pragmas)
    expanded = parser.parse.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
    expanded.token_event.input_start.should eq(0)
    expanded.token_event.byte_parts.first.as(Iyi::DiagnosticEmissionPart::AstAnchor).source_origin.should eq(original)
    expanded.token_event.byte_parts.first.emitter_origin.should eq(emitter)
    expanded.invocation_origin.should eq(invocation)
  end

  it "uses the actual arrow token extent for generated macro text and rejects missing coverage" do
    text = "-> { 1 }"
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 9, "Macro", "keyword")
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 20, "MacroDirective", "expression")
    generated = Iyi::DiagnosticGeneratedText.new(0, text.bytesize, emitter, Iyi::DiagnosticMacroProducer::MacroId)
    emission = Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, [] of Iyi::DiagnosticMacroClaim, [generated], [] of Iyi::DiagnosticMacroNameFragment)
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}",
      {0 => [emission] of Iyi::Lexer::LocPragma})
    origin = parser.parse.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
    origin.token_event.byte_parts.should eq([Iyi::DiagnosticEmissionPart::Generated.new(0, 2, emitter, Iyi::DiagnosticMacroProducer::MacroId)])

    missing = Iyi::Parser.new(text)
    missing.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", nil)
    expect_raises(ArgumentError, /unauthorized macro anchor/) { missing.parse }
  end

  it "records only the operator when a signed numeric token is split" do
    text = "1+2"
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 9, "Macro", "keyword")
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 20, "MacroDirective", "expression")
    generated = Iyi::DiagnosticGeneratedText.new(0, text.bytesize, emitter, Iyi::DiagnosticMacroProducer::MacroId)
    emission = Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, [] of Iyi::DiagnosticMacroClaim, [generated], [] of Iyi::DiagnosticMacroNameFragment)
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}",
      {0 => [emission] of Iyi::Lexer::LocPragma})
    origin = parser.parse.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
    origin.token_event.selection.should eq(Iyi::DiagnosticTokenSelection::SignedNumberSign)
    origin.token_event.byte_parts.should eq([Iyi::DiagnosticEmissionPart::Generated.new(1, 2, emitter, Iyi::DiagnosticMacroProducer::MacroId)])
  end

  it "rejects a spliced anchor that overlaps generated text" do
    text = "-> { 1 }"
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 9, "Macro", "keyword")
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 20, "MacroDirective", "expression")
    original = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 35, "ProcLiteral", "arrow")
    anchor = diagnostic_macro_claim(0, 2, "ProcLiteral", "arrow", Iyi::DiagnosticAnchorEvidence::Spliced.new(original), emitter)
    generated = Iyi::DiagnosticGeneratedText.new(0, text.bytesize, emitter, Iyi::DiagnosticMacroProducer::MacroId)
    emission = Iyi::Lexer::LocDiagnosticEmission.new(text.bytesize, [anchor], [generated], [] of Iyi::DiagnosticMacroNameFragment)
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, definition, "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}",
      {0 => [emission] of Iyi::Lexer::LocPragma})
    expect_raises(ArgumentError, /macro anchor overlaps generated text/) { parser.parse }
  end

  it "retains a source closure inside a macro-constructed array" do
    source_parser = Iyi::Parser.new("-> { 1 }")
    source_parser.filename = "/src/main.cr"
    source_parser.diagnostic_source_file = "/src/main.cr"
    source_parser.diagnostic_capture = true
    closure = source_parser.parse.as(Iyi::ProcLiteral)
    original = closure.diagnostic_origin.not_nil!

    macro_parser = Iyi::Parser.new("macro foo(x)\n{{ [x, 7] }}\nend")
    macro_parser.filename = "/src/macros.cr"
    macro_parser.diagnostic_source_file = "/src/macros.cr"
    macro_parser.diagnostic_capture = true
    macro_node = macro_parser.parse.as(Iyi::Macro)
    program, _, call = prepare_macro_call("{{ x }}") { {x: closure} }
    program.diagnostic_capture = true
    invocation = Iyi::DiagnosticOrigin::Written.new("source-file:/src/main.cr", "/src/main.cr", 10, "Call", "method")
    call.diagnostic_origin = invocation
    text, pragmas = program.expand_macro(macro_node, call, program, program)
    parser = Iyi::Parser.new(text)
    parser.diagnostic_expansion(invocation, macro_node.diagnostic_origin.not_nil!,
      "sha256:#{::Crystal::Digest::SHA256.hexdigest(text)}", pragmas)
    array = parser.parse.as(Iyi::ArrayLiteral)
    array_origin = array.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
    array_origin.token_event.byte_parts.any? { |part| part.is_a?(Iyi::DiagnosticEmissionPart::AstAnchor) }.should be_false
    closure_origin = array.elements.first.diagnostic_origin.as(Iyi::DiagnosticOrigin::Expanded)
    closure_origin.token_event.byte_parts.first.as(Iyi::DiagnosticEmissionPart::AstAnchor).source_origin.should eq(original)
    closure_origin.token_event.byte_parts.first.emitter_origin.should_not be_nil

    fragment_io = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    array.to_s(fragment_io, diagnostic_fragment: builder)
    fragment_text = fragment_io.to_s
    captured = builder.finish("fixture", fragment_text)
    anchors = captured.anchors
    key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
    declaration = type_declaration("Box", "class", fields: [{"@factory", "Array", fragment_text}])
    artifact = sample_artifact(types: [declaration], source_path: "/absent/array.cr")
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, captured.text_sha256, captured.events, anchors))
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      restored = Iyi::IyiMod.read(path)
      carried_text = restored.exports.types.first.fields.first[2]
      fragment = restored.diagnostic_provenance.not_nil!.fragments[key]
      consumer = Iyi::Parser.new(carried_text)
      consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried_text.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
      carried = consumer.parse.as(Iyi::ArrayLiteral)
      carried.diagnostic_origin.should eq(array_origin)
      carried.elements.first.diagnostic_origin.should eq(closure_origin)
      reemitted_io = IO::Memory.new
      rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      carried.to_s(reemitted_io, diagnostic_fragment: rebuilder)
      reemitted_io.to_s.should eq(carried_text)
      rebuilder.finish("fixture", reemitted_io.to_s).should eq(captured)
      Iyi::IyiMod.write restored, path
      Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq(anchors)
    end

    closure.diagnostic_origin = nil
    expect_raises(ArgumentError) { program.expand_macro(macro_node, call, program, program) }
  end

  it "distinguishes an inline macro directive and its synthetic definition" do
    directive = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "MacroDirective", "control")
    definition = Iyi::DiagnosticOrigin::Synthetic.new(directive, "inline_macro_definition", "macro")
    event = Iyi::DiagnosticTokenEvent.new(4, 6, "->", "->", "Iyi", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::Generated.new(4, 6, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart)
    expanded = Iyi::DiagnosticOrigin::Expanded.new(directive, definition, "sha256:" + "0" * 64,
      "ProcLiteral", "arrow", nil, event, Iyi::DiagnosticAnchorUse::Direct.new)
    expanded.valid_for_anchor?("ProcLiteral", "arrow").should be_true
    Iyi::DiagnosticOrigin.from_json(expanded.as_json).should eq(expanded)
  end

  it "round trips parent-first origin records and rejects a forward reference" do
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 5, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/src/macros.iyi", 9, "Macro", "keyword")
    splice = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 35, "Block", "opener")
    event = Iyi::DiagnosticTokenEvent.new(4, 5, "{", "{", "Iyi", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::AstAnchor.new(4, 5, nil, splice)] of Iyi::DiagnosticEmissionPart)
    expanded = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, "sha256:" + "0" * 64,
      "Block", "opener", nil, event, Iyi::DiagnosticAnchorUse::Direct.new)
    origin = Iyi::DiagnosticOrigin::Synthetic.new(expanded, "block_to_proc", "proc")
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    decoded = Iyi::IyiMod::DiagnosticOrigins.read(io)
    decoded.parent(index).should eq(origin)

    corrupt = IO::Memory.new
    corrupt.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    corrupt.write_byte 3_u8
    corrupt.write_bytes 0_u32, Iyi::IyiMod::FORMAT
    corrupt.rewind
    expect_raises(ArgumentError) { Iyi::IyiMod::DiagnosticOrigins.read(corrupt) }

    unknown = IO::Memory.new
    unknown.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    unknown.write_byte 255_u8
    unknown.rewind
    expect_raises(ArgumentError, /unknown diagnostic origin tag/) { Iyi::IyiMod::DiagnosticOrigins.read(unknown) }

    unknown_derivation = IO::Memory.new
    unknown_derivation.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    unknown_derivation.write_byte 4_u8
    unknown_derivation.write_byte 255_u8
    unknown_derivation.rewind
    expect_raises(ArgumentError, /unknown diagnostic name derivation tag/) do
      Iyi::IyiMod::DiagnosticOrigins.read(unknown_derivation)
    end

    parents = Iyi::IyiMod::DiagnosticOrigins.new
    parents.intern(invocation)
    parents.intern(definition)
    parent_bytes = IO::Memory.new
    parents.write(parent_bytes)
    bad_part = IO::Memory.new
    bad_part.write_bytes 3_u32, Iyi::IyiMod::FORMAT
    bad_part.write(parent_bytes.to_slice[4..])
    bad_part.write_byte 2_u8
    bad_part.write_bytes 0_u32, Iyi::IyiMod::FORMAT
    bad_part.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    Iyi::IyiMod::DiagnosticOrigins.write_string(bad_part, "sha256:" + "0" * 64)
    Iyi::IyiMod::DiagnosticOrigins.write_string(bad_part, "ProcLiteral")
    Iyi::IyiMod::DiagnosticOrigins.write_string(bad_part, "arrow")
    bad_part.write_byte 0_u8
    bad_part.write_bytes 0_u32, Iyi::IyiMod::FORMAT
    bad_part.write_bytes 2_u32, Iyi::IyiMod::FORMAT
    Iyi::IyiMod::DiagnosticOrigins.write_string(bad_part, "->")
    Iyi::IyiMod::DiagnosticOrigins.write_string(bad_part, "->")
    bad_part.write_byte 1_u8
    bad_part.write_byte 0_u8
    bad_part.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    bad_part.write_byte 255_u8
    bad_part.write_bytes 0_u32, Iyi::IyiMod::FORMAT
    bad_part.write_bytes 2_u32, Iyi::IyiMod::FORMAT
    bad_part.write_bytes UInt32::MAX, Iyi::IyiMod::FORMAT
    bad_part.write_bytes 0_u32, Iyi::IyiMod::FORMAT
    bad_part.rewind
    expect_raises(ArgumentError, /unknown macro emission part tag/) { Iyi::IyiMod::DiagnosticOrigins.read(bad_part) }

    invalid_utf8 = IO::Memory.new
    invalid_utf8.write_bytes 1_u32, Iyi::IyiMod::FORMAT
    invalid_utf8.write_byte 255_u8
    invalid_utf8.rewind
    expect_raises(ArgumentError, /invalid UTF-8/) { Iyi::IyiMod::DiagnosticOrigins.read_string(invalid_utf8) }
  end

  it "round trips composed names and source-name slots with distinct parents" do
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/caller.cr", 4, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/absent/macros.cr", 2, "Macro", "keyword")
    lexical = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/caller.cr", 0, "Call", "method")
    binding = Iyi::DiagnosticOrigin::Synthetic.new(lexical, "local_binding", "assignment")
    token = Iyi::DiagnosticSourceNameToken.new(lexical, binding, "method_name",
      ::Crystal::Digest::SHA256.hexdigest("empty"), 5, 0, 5, "Crystal", "IDENT", "empty")
    parts = [
      Iyi::DiagnosticEmissionPart::Generated.new(0, 2, nil, Iyi::DiagnosticMacroProducer::MacroTemplate),
      Iyi::DiagnosticEmissionPart::NameSplice.new(2, 7, nil, Iyi::DiagnosticNameValue::Observed.new(token)),
    ] of Iyi::DiagnosticEmissionPart
    event = Iyi::DiagnosticTokenEvent.new(0, 7, "CLASS_VAR", "@@empty", "Crystal", Iyi::DiagnosticTokenSelection::Whole, parts)
    expanded = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition,
      "sha256:" + ::Crystal::Digest::SHA256.hexdigest("@@empty"),
      "Name", "class_variable", "class_variable", event, Iyi::DiagnosticAnchorUse::Direct.new)
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
    composed_token = Iyi::DiagnosticSourceNameToken.new(expanded, nil, "class_variable",
      ::Crystal::Digest::SHA256.hexdigest("@@empty"), 7, 0, 7, "Crystal", "CLASS_VAR", "@@empty")
    slots = {slot => [Iyi::DiagnosticNameValue::Observed.new(composed_token)] of Iyi::DiagnosticNameValue}
    output_event = Iyi::DiagnosticTokenEvent.new(0, 7, "CLASS_VAR", "@@empty", "Crystal", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::NameSplice.new(0, 7, nil, Iyi::DiagnosticNameValue::Observed.new(composed_token))] of Iyi::DiagnosticEmissionPart)
    anchor = Iyi::DiagnosticAnchor.new(0, "Name", "class_variable", expanded, slots, 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
    fragment = Iyi::IyiMod::DiagnosticFragment.new("body:composed",
      ::Crystal::Digest::SHA256.hexdigest("@@empty"), [output_event], [anchor])
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(fragment)
    bytes = section.encode
    decoded = Iyi::IyiMod::DiagnosticSection.decode(bytes)
    restored = decoded.fragments["body:composed"].anchors.first
    restored.should eq(anchor)
    restored.origin.as(Iyi::DiagnosticOrigin::Expanded).token_event.byte_parts.should eq(parts)
    restored.name_slots[slot].first.as(Iyi::DiagnosticNameValue::Observed).source_token.lexical_origin.should eq(expanded)
    decoded.encode.should eq(bytes)

    key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
    declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", "@@empty"}])
    artifact = sample_artifact(types: [declaration], source_path: "/absent/composed.cr")
    artifact_section = Iyi::IyiMod::DiagnosticSection.new
    artifact_section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, fragment.text_sha256, fragment.events, [anchor]))
    artifact.diagnostic_provenance = artifact_section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      imported = Iyi::IyiMod.read(path)
      carried_text = imported.exports.types.first.fields.first[2]
      carried_fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
      parser = Iyi::Parser.new(carried_text)
      parser.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried_text.bytesize, carried_fragment.text_sha256, carried_fragment.events, carried_fragment.anchors)]
      node = parser.parse
      parser.diagnostic_check_consumed
      emitted = IO::Memory.new
      rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      node.to_s(emitted, diagnostic_fragment: rebuilder)
      emitted.to_s.should eq(carried_text)
      rebuilder.finish("body:composed", emitted.to_s).should eq(fragment)
      Iyi::IyiMod.write imported, path
      Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq([anchor])
    end

    old = IO::Memory.new
    old.write_bytes 3_u32, Iyi::IyiMod::FORMAT
    expect_raises(ArgumentError, /unsupported diagnostic section schema/) do
      Iyi::IyiMod::DiagnosticSection.decode(old.to_slice)
    end
    expect_raises(ArgumentError) do
      Iyi::DiagnosticEmissionPart::NameSplice.new(2, 6, nil, Iyi::DiagnosticNameValue::Observed.new(token))
    end
    expect_raises(ArgumentError) do
      invalid_event = Iyi::DiagnosticTokenEvent.new(0, 7, "CLASS_VAR", "@@other", "Crystal", Iyi::DiagnosticTokenSelection::Whole, parts)
      Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, "sha256:" + "0" * 64,
        "Name", "class_variable", "class_variable", invalid_event, Iyi::DiagnosticAnchorUse::Direct.new)
    end
    expect_raises(ArgumentError) do
      short_parts = [Iyi::DiagnosticEmissionPart::Generated.new(0, 1, nil, Iyi::DiagnosticMacroProducer::MacroTemplate),
                     Iyi::DiagnosticEmissionPart::NameSplice.new(2, 7, nil, Iyi::DiagnosticNameValue::Observed.new(token))] of Iyi::DiagnosticEmissionPart
      invalid_event = Iyi::DiagnosticTokenEvent.new(0, 7, "CLASS_VAR", "@@empty", "Crystal", Iyi::DiagnosticTokenSelection::Whole, short_parts)
      Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, "sha256:" + "0" * 64,
        "Name", "class_variable", "class_variable", invalid_event, Iyi::DiagnosticAnchorUse::Direct.new)
    end
    expect_raises(ArgumentError) do
      bad_slots = {slot => [] of Iyi::DiagnosticNameValue}
      bad_anchor = Iyi::DiagnosticAnchor.new(0, "Name", "class_variable", expanded, bad_slots, 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
      Iyi::IyiMod::DiagnosticSection.new.add_fragment(
        Iyi::IyiMod::DiagnosticFragment.new("body:bad", fragment.text_sha256, fragment.events, [bad_anchor]))
    end
    expect_raises(ArgumentError) do
      Iyi::DiagnosticSourceNameToken.new(lexical, binding, "method_name", "0" * 64, 4, 0, 5, "Crystal", "IDENT", "empty")
    end
    other = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/other.cr", 0, "Call", "method")
    expect_raises(ArgumentError) do
      Iyi::DiagnosticSourceNameToken.new(other, binding, "method_name", "0" * 64, 5, 0, 5, "Crystal", "IDENT", "empty")
    end
  end

  it "transports shared-event head and payload uses with independent parent origins" do
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/main.cr", 0, "Call", "method")
    definition = Iyi::DiagnosticOrigin::Written.new("app/macros", "/absent/macro.cr", 0, "Macro", "keyword")
    source = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/source.cr", 0, "Literal", "array")
    emitter = Iyi::DiagnosticOrigin::Written.new("app/macros", "/absent/macro.cr", 9, "MacroDirective", "expression")
    guard = "sha256:" + ::Crystal::Digest::SHA256.hexdigest("Set")
    event = Iyi::DiagnosticTokenEvent.new(0, 3, "CONST", "Set", "Crystal", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::Generated.new(0, 3, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart)
    child = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, guard,
      "Name", "path_segment", "path_segment", event, Iyi::DiagnosticAnchorUse::Direct.new)
    use = Iyi::DiagnosticAnchorUse::HeadOf.new(Iyi::DiagnosticHeadRule::NamedArrayHead,
      Iyi::DiagnosticAnchorEvidence::Spliced.new(source), Iyi::DiagnosticHead::Anchor.new(child), emitter)
    parent = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, guard,
      "Literal", "array", nil, event, use)

    regex_event = Iyi::DiagnosticTokenEvent.new(0, 1, "DELIMITER_START", "/", "Crystal", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::Generated.new(0, 1, nil, Iyi::DiagnosticMacroProducer::MacroTemplate)] of Iyi::DiagnosticEmissionPart)
    regex_guard = "sha256:" + ::Crystal::Digest::SHA256.hexdigest("/")
    owner = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, regex_guard,
      "Literal", "regex", nil, regex_event, Iyi::DiagnosticAnchorUse::Direct.new)
    payload_use = Iyi::DiagnosticAnchorUse::PayloadOf.new(Iyi::DiagnosticPayloadRule::RegexInterpolationPayload,
      Iyi::DiagnosticAnchorEvidence::DerivedFromOwner.new, owner, nil)
    payload = Iyi::DiagnosticOrigin::Expanded.new(invocation, definition, regex_guard,
      "Literal", "interpolation", nil, regex_event, payload_use)
    table = Iyi::IyiMod::DiagnosticOrigins.new
    parent_index = table.intern(parent)
    payload_index = table.intern(payload)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    decoded = Iyi::IyiMod::DiagnosticOrigins.read(io)
    decoded.parent(parent_index).should eq(parent)
    decoded.parent(payload_index).should eq(payload)
    decoded.parent(parent_index).as(Iyi::DiagnosticOrigin::Expanded).anchor_use.should eq(use)
    decoded.parent(parent_index).as(Iyi::DiagnosticOrigin::Expanded).anchor_use.as(Iyi::DiagnosticAnchorUse::HeadOf).emitter_origin.should eq(emitter)
    decoded.parent(payload_index).as(Iyi::DiagnosticOrigin::Expanded).anchor_use.should eq(payload_use)
  end

  it "refuses a bound projection without an authoritative source inventory" do
    text = "Root::Thing"
    guard = ::Crystal::Digest::SHA256.hexdigest(text)
    root_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", 0, "Name", "path_segment")
    type_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", 6, "Name", "path_segment")
    root_token = Iyi::DiagnosticSourceNameToken.new(root_origin, nil, "path_segment", guard, text.bytesize, 0, 4, "Crystal", "CONST", "Root")
    type_token = Iyi::DiagnosticSourceNameToken.new(type_origin, nil, "path_segment", guard, text.bytesize, 6, 11, "Crystal", "CONST", "Thing")
    names = [
      Iyi::DiagnosticBoundNameSource.new(0, 4, Iyi::DiagnosticNameValue::Observed.new(root_token)),
      Iyi::DiagnosticBoundNameSource.new(6, 11, Iyi::DiagnosticNameValue::Observed.new(type_token)),
    ]
    error = expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.bound_projection(Iyi::DiagnosticBoundProducer::StripRoot.new("Root"),
        guard, text, names, "Thing", "Crystal", 0, 5, "CONST", "path_segment")
    end
    error.message.should eq("bound projection requires authoritative source inventory")
  end

  it "transports bound projections with every source-name contribution" do
    text = "Root::Thing"
    guard = ::Crystal::Digest::SHA256.hexdigest(text)
    root_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", 0, "Name", "path_segment")
    type_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/bind.cr", 6, "Name", "path_segment")
    root_token = Iyi::DiagnosticSourceNameToken.new(root_origin, nil, "path_segment", guard, text.bytesize, 0, 4, "Crystal", "CONST", "Root")
    type_token = Iyi::DiagnosticSourceNameToken.new(type_origin, nil, "path_segment", guard, text.bytesize, 6, 11, "Crystal", "CONST", "Thing")
    names = [
      Iyi::DiagnosticBoundNameSource.new(0, 4, Iyi::DiagnosticNameValue::Observed.new(root_token)),
      Iyi::DiagnosticBoundNameSource.new(6, 11, Iyi::DiagnosticNameValue::Observed.new(type_token)),
    ]
    producer = Iyi::DiagnosticBoundProducer::StripRoot.new("Root")
    origin = Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, guard, text, names, "Thing", "Crystal",
      0, 5, "CONST", "path_segment")
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    restored = Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored.should eq(origin)
    restored.source_names.should eq(names)
    restored.producer.should eq(producer)
    other_origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/other.cr", 6, "Name", "path_segment")
    other_token = Iyi::DiagnosticSourceNameToken.new(other_origin, nil, "path_segment", guard, text.bytesize, 6, 11, "Crystal", "CONST", "Thing")
    changed_names = [names.first, Iyi::DiagnosticBoundNameSource.new(6, 11, Iyi::DiagnosticNameValue::Observed.new(other_token))]
    changed = Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, guard, text, changed_names, "Thing", "Crystal",
      0, 5, "CONST", "path_segment")
    changed.should_not eq(origin)
    table.intern(changed).should_not eq(index)

    output = "Thing"
    value = Iyi::DiagnosticNameValue::Derived.new(origin)
    slot = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::PathSegment, 0)
    event = Iyi::DiagnosticTokenEvent.new(0, 5, "CONST", output, "Crystal", Iyi::DiagnosticTokenSelection::Whole,
      [Iyi::DiagnosticEmissionPart::NameSplice.new(0, 5, nil, value)] of Iyi::DiagnosticEmissionPart)
    anchor = Iyi::DiagnosticAnchor.new(0, "Name", "path_segment", origin,
      {slot => [value] of Iyi::DiagnosticNameValue}, 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
    key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
    declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", output}])
    artifact = sample_artifact(types: [declaration], source_path: "/absent/bind.cr")
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, ::Crystal::Digest::SHA256.hexdigest(output), [event], [anchor]))
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      imported = Iyi::IyiMod.read(path)
      fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
      consumer = Iyi::Parser.new(output)
      consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, output.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
      node = consumer.parse
      consumer.diagnostic_check_consumed
      printed = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      node.to_s(printed, diagnostic_fragment: builder)
      replayed = builder.finish(key, printed.to_s)
      replayed.should eq(fragment)
      Iyi::IyiMod.write imported, path
      Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].should eq(fragment)
    end

    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, guard, text, names, "Wrong", "Crystal",
        0, 5, "CONST", "path_segment")
    end
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.bound_projection(producer, "0" * 64, text, names, "Thing", "Crystal",
        0, 5, "CONST", "path_segment")
    end
  end

  it "round trips each closed bound producer tag and rejects nonboolean restriction flags" do
    definition = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/main.cr", 0, "Def", "keyword")
    variable = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/main.cr", 4, "Name", "class_variable")
    producers = [
      Iyi::DiagnosticBoundProducer::StripRoot.new("Root"),
      Iyi::DiagnosticBoundProducer::ForeignType.new("lib", "Thing", "Lib::Thing"),
      Iyi::DiagnosticBoundProducer::AliasType.new("Owner", "Alias", "Target"),
      Iyi::DiagnosticBoundProducer::SelfReturn.new("Owner", "new", "self"),
      Iyi::DiagnosticBoundProducer::SemanticSignatureType.new(definition, "return_type", nil, "Thing"),
      Iyi::DiagnosticBoundProducer::UninitializedClassVar.new(variable, "Owner", "@@item", "Thing"),
      Iyi::DiagnosticBoundProducer::ConstantAccessor.new(definition, "", "Thing", "Name"),
      Iyi::DiagnosticBoundProducer::ResolvedRestriction.new("Owner", "Thing", "Other", "Root", true),
    ] of Iyi::DiagnosticBoundProducer
    table = Iyi::IyiMod::DiagnosticOrigins.new
    table.intern(definition)
    table.intern(variable)
    producers.each do |producer|
      io = IO::Memory.new
      table.write_bound_producer(io, producer)
      io.rewind
      table.read_bound_producer(io).should eq(producer)
    end
    malformed = IO::Memory.new
    malformed.write_byte 8_u8
    {"Owner", "Thing", "Other", "Root"}.each { |text| Iyi::IyiMod::DiagnosticOrigins.write_string(malformed, text) }
    malformed.write_byte 2_u8
    malformed.rewind
    expect_raises(ArgumentError, /invalid restriction global marker/) { table.read_bound_producer(malformed) }
  end

  it "transports implicit module self with its actual header origin" do
    header = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/main.iyi", 0, "ModuleHeader", "keyword")
    origin = Iyi::DiagnosticOrigin::DerivedName.implicit_module_self(header)
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    restored = Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored.should eq(origin)
    restored.module_header_origin.should eq(header)
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin::DerivedName.implicit_module_self(
      Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/main.iyi", 0, "Def", "keyword")) }
  end

  it "transports module header paths with their complete source segments" do
    text = "module foo/bar"
    digest = ::Crystal::Digest::SHA256.hexdigest(text)
    header = Iyi::DiagnosticOrigin::Written.new("source-file:/absent/main.iyi", "/absent/main.iyi", 0, "ModuleHeader", "keyword")
    first = Iyi::DiagnosticOrigin::Written.new("source-file:/absent/main.iyi", "/absent/main.iyi", 7, "Name", "module_segment")
    second = Iyi::DiagnosticOrigin::Written.new("source-file:/absent/main.iyi", "/absent/main.iyi", 11, "Name", "module_segment")
    segments = [
      Iyi::DiagnosticSourceNameToken.new(first, nil, "module_segment", digest, text.bytesize, 7, 10, "Iyi", "IDENT", "foo"),
      Iyi::DiagnosticSourceNameToken.new(second, nil, "module_segment", digest, text.bytesize, 11, 14, "Iyi", "IDENT", "bar"),
    ]
    origin = Iyi::DiagnosticOrigin::DerivedName.module_header_path(header, segments, nil, 1)
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    restored = Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored.should eq(origin)
    restored.module_header_origin.should eq(header)
    restored.source_segments.should eq(segments)
    restored.package_name.should be_nil
    restored.result_index.should eq(1)
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin::DerivedName.module_header_path(header, segments, nil, 2) }
  end

  it "round trips type-sugar source syntax witnesses without inventing identifier tokens" do
    text = "Int32*"
    source = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/types.cr", 5, "TypeSyntax", "token")
    witness = Iyi::DiagnosticSourceSyntaxToken.new(source, ::Crystal::Digest::SHA256.hexdigest(text),
      text.bytesize, 5, 6, "Crystal", "*", "*")
    origin = Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::Pointer, [witness],
      Iyi::DiagnosticTypeSugarResult::Pointer, 0)
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(origin)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    restored = Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).as(Iyi::DiagnosticOrigin::DerivedName)
    restored.should eq(origin)
    restored.witnesses.should eq([witness])
    restored.production.should eq(Iyi::DiagnosticTypeSugar::Pointer)
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.type_sugar(Iyi::DiagnosticTypeSugar::Pointer, [witness],
        Iyi::DiagnosticTypeSugarResult::Union, 0)
    end
  end

  it "restores type-sugar witnesses after a source-absent artifact roundtrip" do
    source = "def f(x : Int32*)\n  nil\nend"
    parser = Iyi::Parser.new(source)
    parser.filename = "/absent/types.cr"
    parser.diagnostic_source_file = "/absent/types.cr"
    parser.diagnostic_capture = true
    definition = parser.parse.as(Iyi::Def)
    io = IO::Memory.new
    builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
    definition.to_s(io, diagnostic_fragment: builder)
    text = io.to_s
    recorded = builder.finish("recorded", text)
    sugar = recorded.anchors.compact_map { |anchor| anchor.origin.as?(Iyi::DiagnosticOrigin::DerivedName) }
      .find { |origin| origin.derivation_kind == "TypeSugar" }.not_nil!
    sugar.witnesses.first.raw_text.should eq("*")
    sugar.witnesses.first.input_sha256.should eq(::Crystal::Digest::SHA256.hexdigest(source))
    key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
    declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", text}])
    artifact = sample_artifact(types: [declaration], source_path: "/absent/types.cr")
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, recorded.text_sha256, recorded.events, recorded.anchors))
    artifact.diagnostic_provenance = section
    with_temporary_file do |path|
      Iyi::IyiMod.write artifact, path
      imported = Iyi::IyiMod.read(path)
      fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
      carried = imported.exports.types.first.fields.first[2]
      consumer = Iyi::Parser.new(carried)
      consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
      restored = consumer.parse
      consumer.diagnostic_check_consumed
      output = IO::Memory.new
      rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      restored.to_s(output, diagnostic_fragment: rebuilder)
      rebuilder.finish("recorded", output.to_s).should eq(recorded)
      Iyi::IyiMod.write imported, path
      Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].should eq(fragment)
    end
  end

  it "interns derived names before macro compositions and rejects forged derivations" do
    source = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/parameter.cr", 0, "Name", "parameter")
    token = Iyi::DiagnosticSourceNameToken.new(source, nil, "parameter",
      ::Crystal::Digest::SHA256.hexdigest("@x"), 2, 0, 2, "Crystal", "INSTANCE_VAR", "@x")
    definition = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/parameter.cr", 5, "Def", "keyword")
    derived = Iyi::DiagnosticOrigin::DerivedName.new(token, definition, "positional", 0,
      "LocalValue", "StripVariablePrefix", nil)
    value = Iyi::DiagnosticNameValue::Derived.new(derived)
    value.rendered_text.should eq("x")
    invocation = Iyi::DiagnosticOrigin::Written.new("app/main", "/absent/caller.cr", 0, "Call", "method")
    macro_origin = Iyi::DiagnosticOrigin::Written.new("app/macros", "/absent/macros.cr", 0, "Macro", "keyword")
    parts = [
      Iyi::DiagnosticEmissionPart::Generated.new(0, 6, nil, Iyi::DiagnosticMacroProducer::MacroTemplate),
      Iyi::DiagnosticEmissionPart::NameSplice.new(6, 7, nil, value),
    ] of Iyi::DiagnosticEmissionPart
    event = Iyi::DiagnosticTokenEvent.new(0, 7, "IDENT", "prefixx", "Crystal", Iyi::DiagnosticTokenSelection::Whole, parts)
    expanded = Iyi::DiagnosticOrigin::Expanded.new(invocation, macro_origin,
      "sha256:" + ::Crystal::Digest::SHA256.hexdigest("prefixx"),
      "Call", "method", "method_name", event, Iyi::DiagnosticAnchorUse::Direct.new)
    table = Iyi::IyiMod::DiagnosticOrigins.new
    index = table.intern(expanded)
    io = IO::Memory.new
    table.write(io)
    io.rewind
    restored = Iyi::IyiMod::DiagnosticOrigins.read(io).parent(index).as(Iyi::DiagnosticOrigin::Expanded)
    restored.should eq(expanded)
    restored.token_event.byte_parts.last.as(Iyi::DiagnosticEmissionPart::NameSplice).source_name.should eq(value)
    unknown = IO::Memory.new
    unknown.write_byte 255_u8
    unknown.rewind
    expect_raises(ArgumentError, /unknown diagnostic name value tag/) { table.read_name_value(unknown) }
    wrong_origin = IO::Memory.new
    wrong_origin.write_byte 2_u8
    wrong_origin.write_bytes table.intern(invocation), Iyi::IyiMod::FORMAT
    wrong_origin.rewind
    expect_raises(ArgumentError, /not derived/) { table.read_name_value(wrong_origin) }
    forward = IO::Memory.new
    forward.write_byte 2_u8
    forward.write_bytes table.entries.size.to_u32, Iyi::IyiMod::FORMAT
    forward.rewind
    expect_raises(ArgumentError, /invalid diagnostic origin parent index/) { table.read_name_value(forward) }
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.new(token, definition, "positional", 0, "Target", "StripVariablePrefix", nil)
    end
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.new(token, definition, "block", 1, "Argument", "StripVariablePrefix", nil)
    end
    expect_raises(ArgumentError) do
      Iyi::DiagnosticOrigin::DerivedName.new(token, definition, "positional", 0, "Argument", "FreshParameterName", nil)
    end
  end

  it "carries normalized variable parameters through a source-absent artifact and re-emission" do
    {"@x", "@@x", "@select", "@éclair"}.each do |parameter|
      original = "def f(#{parameter})\n  nil\nend"
      producer = Iyi::Parser.new(original)
      producer.filename = "/absent/parameter.cr"
      producer.diagnostic_source_file = "/absent/parameter.cr"
      producer.diagnostic_capture = true
      definition = producer.parse.as(Iyi::Def)
      printed = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      definition.to_s(printed, diagnostic_fragment: builder)
      text = printed.to_s
      recorded = builder.finish("recorded", text)
      anchors = recorded.anchors
      derived = anchors.compact_map { |anchor| anchor.origin.as?(Iyi::DiagnosticOrigin::DerivedName) }
      derived.map(&.result).should contain("Argument")
      derived.map(&.result).should contain("Target")
      derived.map(&.result).should contain("LocalValue")
      derived.each do |name|
        name.source_token.not_nil!.raw_text.should eq(parameter)
        name.source_token.not_nil!.input_sha256.should eq(::Crystal::Digest::SHA256.hexdigest(original))
        name.definition_origin.should eq(definition.diagnostic_origin)
      end
      if parameter == "@select"
        derived.select { |name| {"Argument", "LocalValue"}.includes?(name.result) }.each do |name|
          name.projection.should eq("FreshParameterName")
          name.fresh_index.should_not be_nil
        end
      end

      key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
      declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", text}])
      artifact = sample_artifact(types: [declaration], source_path: "/absent/parameter.cr")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, recorded.text_sha256, recorded.events, anchors))
      artifact.diagnostic_provenance = section
      with_temporary_file do |path|
        Iyi::IyiMod.write artifact, path
        imported = Iyi::IyiMod.read(path)
        fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
        carried = imported.exports.types.first.fields.first[2]
        consumer = Iyi::Parser.new(carried)
        consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
        restored = consumer.parse.as(Iyi::Def)
        consumer.diagnostic_check_consumed
        reprinted = IO::Memory.new
        rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
        restored.to_s(reprinted, diagnostic_fragment: rebuilder)
        reprinted.to_s.should eq(text)
        rebuilder.finish("recorded", reprinted.to_s).should eq(recorded)
        Iyi::IyiMod.write imported, path
        Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq(anchors)

        missing = fragment.anchors.reject { |anchor| anchor.origin.is_a?(Iyi::DiagnosticOrigin::DerivedName) }
        broken = Iyi::Parser.new(carried)
        expect_raises(ArgumentError) do
          broken.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, missing)]
          broken.parse
          broken.diagnostic_check_consumed
        end
      end
    end
  end

  it "carries enum members and special-global derivations through source-absent artifacts" do
    {"enum E\n  A = build()\n  B\nend", "$~", "$?", "$~ = nil", "$? = nil", "$~.foo", "$?.foo", "$0", "$1", "$1?"}.each do |source|
      producer = Iyi::Parser.new(source)
      producer.filename = "/absent/special.cr"
      producer.diagnostic_source_file = "/absent/special.cr"
      producer.diagnostic_capture = true
      original = producer.parse
      printed = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      original.to_s(printed, diagnostic_fragment: builder)
      text = printed.to_s
      recorded = builder.finish("recorded", text)
      anchors = recorded.anchors
      Iyi::Parser.new(source).parse.to_s.should eq(text)
      key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
      declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", text}])
      artifact = sample_artifact(types: [declaration], source_path: "/absent/special.cr")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, recorded.text_sha256, recorded.events, anchors))
      artifact.diagnostic_provenance = section
      with_temporary_file do |path|
        Iyi::IyiMod.write artifact, path
        imported = Iyi::IyiMod.read(path)
        fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
        carried = imported.exports.types.first.fields.first[2]
        consumer = Iyi::Parser.new(carried)
        consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
        restored = consumer.parse
        consumer.diagnostic_check_consumed
        if source.starts_with?("enum")
          enum = restored.as(Iyi::EnumDef)
          enum.members.size.should eq(2)
          enum.members.each do |member|
            value = member.as(Iyi::Arg).diagnostic_name_slots[
              Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::EnumMember)].first
            value.as(Iyi::DiagnosticNameValue::Observed).source_token.context.should eq("enum_member")
          end
        elsif source == "$~" || source == "$?"
          value = restored.as(Iyi::Global).diagnostic_name_slots[
            Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)].first
          value.as(Iyi::DiagnosticNameValue::Observed).source_token.raw_text.should eq(source)
        elsif source.includes?(" = ")
          value = restored.as(Iyi::Assign).target.as(Iyi::Var).diagnostic_name_slots[
            Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)].first
          value.as(Iyi::DiagnosticNameValue::Observed).source_token.raw_text.should eq(source.byte_slice(0, 2))
        elsif source.ends_with?(".foo")
          value = restored.as(Iyi::Call).obj.as(Iyi::Global).diagnostic_name_slots[
            Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)].first
          value.as(Iyi::DiagnosticNameValue::Observed).source_token.raw_text.should eq(source.byte_slice(0, 2))
        else
          call = restored.as(Iyi::Call)
          lookup = call.diagnostic_origin.as(Iyi::DiagnosticOrigin::DerivedName)
          lookup.derivation_kind.should eq("RegexMatchIndex")
          lookup.result.should eq("Lookup")
          lookup.source_token.not_nil!.raw_text.should eq(source)
          match = call.obj.as(Iyi::Global).diagnostic_name_slots[
            Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)].first.as(Iyi::DiagnosticNameValue::Derived).origin
          match.result.should eq("MatchData")
          match.source_token.should eq(lookup.source_token)
        end
        reprinted = IO::Memory.new
        rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
        restored.to_s(reprinted, diagnostic_fragment: rebuilder)
        reprinted.to_s.should eq(text)
        rebuilder.finish("recorded", reprinted.to_s).should eq(recorded)
        Iyi::IyiMod.write imported, path
        Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq(anchors)
        required = if source.starts_with?("enum")
                     fragment.anchors.find { |anchor| anchor.kind == "Name" && anchor.role == "enum_member" }
                   elsif source.starts_with?("$0") || source.starts_with?("$1")
                     fragment.anchors.find { |anchor| anchor.origin.is_a?(Iyi::DiagnosticOrigin::DerivedName) && anchor.kind == "Call" }
                   else
                     fragment.anchors.find { |anchor| anchor.kind == "Name" && anchor.role == "special_global" }
                   end.not_nil!
        missing = fragment.anchors.reject { |anchor| anchor == required }
        broken = Iyi::Parser.new(carried)
        expect_raises(ArgumentError) do
          broken.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, missing)]
          broken.parse
          broken.diagnostic_check_consumed
        end
      end
    end
  end

  it "restores parent and child uses of shared tokens from source-absent artifacts" do
    {"Set {1, 2}", "Set(Int32) {1, 2}", %(Foo{"x" => "y"}),
     %(Foo::Bar{"x" => "y"}), "VALUE = 1", "VALUE : Int32 = 1", "a, b = 1, 2"}.each do |source|
      producer = Iyi::Parser.new(source)
      producer.filename = "/absent/shared.cr"
      producer.diagnostic_source_file = "/absent/shared.cr"
      producer.diagnostic_capture = true
      original = producer.parse
      printed = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      original.to_s(printed, diagnostic_fragment: builder)
      text = printed.to_s
      recorded = builder.finish("recorded", text)
      anchors = recorded.anchors
      Iyi::Parser.new(source).parse.to_s.should eq(text)
      parent = anchors.find { |anchor| {"Literal", "Assign"}.includes?(anchor.kind) }.not_nil!
      child = anchors.find { |anchor| anchor.offset == parent.offset && anchor != parent }.not_nil!
      parent.origin.should_not eq(child.origin)
      key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
      declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", text}])
      artifact = sample_artifact(types: [declaration], source_path: "/absent/shared.cr")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, recorded.text_sha256, recorded.events, anchors))
      artifact.diagnostic_provenance = section
      with_temporary_file do |path|
        Iyi::IyiMod.write artifact, path
        imported = Iyi::IyiMod.read(path)
        fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
        carried = imported.exports.types.first.fields.first[2]
        consumer = Iyi::Parser.new(carried)
        consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
        restored = consumer.parse
        consumer.diagnostic_check_consumed
        reprinted = IO::Memory.new
        rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
        restored.to_s(reprinted, diagnostic_fragment: rebuilder)
        reprinted.to_s.should eq(text)
        rebuilder.finish("recorded", reprinted.to_s).should eq(recorded)
        Iyi::IyiMod.write imported, path
        Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq(anchors)

        {parent, child}.each do |removed|
          incomplete = fragment.anchors.reject { |anchor| anchor == removed }
          broken = Iyi::Parser.new(carried)
          expect_raises(ArgumentError) do
            broken.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, incomplete)]
            broken.parse
            broken.diagnostic_check_consumed
          end
        end
      end
    end
  end

  it "restores interpolation payloads at their owner opener after artifact re-emission" do
    {"/abc\#{foo}/", "/\#{foo}/", "`abc\#{foo}`", "`\#{foo}`"}.each do |source|
      producer = Iyi::Parser.new(source)
      producer.filename = "/absent/payload.cr"
      producer.diagnostic_source_file = "/absent/payload.cr"
      producer.diagnostic_capture = true
      original = producer.parse
      printed = IO::Memory.new
      builder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
      original.to_s(printed, diagnostic_fragment: builder)
      text = printed.to_s
      recorded = builder.finish("recorded", text)
      anchors = recorded.anchors
      Iyi::Parser.new(source).parse.to_s.should eq(text)
      owner = anchors.find { |anchor| anchor.offset == 0 && anchor.role != "interpolation" }.not_nil!
      payload = anchors.find { |anchor| anchor.kind == "Literal" && anchor.role == "interpolation" }.not_nil!
      payload.offset.should eq(owner.offset)
      payload.origin.should_not eq(owner.origin)
      key = Iyi::IyiMod.field_fragment_key("Box", "@factory")
      declaration = type_declaration("Box", "class", fields: [{"@factory", "Object", text}])
      artifact = sample_artifact(types: [declaration], source_path: "/absent/payload.cr")
      section = Iyi::IyiMod::DiagnosticSection.new
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, recorded.text_sha256, recorded.events, anchors))
      artifact.diagnostic_provenance = section
      with_temporary_file do |path|
        Iyi::IyiMod.write artifact, path
        imported = Iyi::IyiMod.read(path)
        fragment = imported.diagnostic_provenance.not_nil!.fragments[key]
        carried = imported.exports.types.first.fields.first[2]
        consumer = Iyi::Parser.new(carried)
        consumer.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, fragment.anchors)]
        restored = consumer.parse
        consumer.diagnostic_check_consumed
        reprinted = IO::Memory.new
        rebuilder = Iyi::DiagnosticFragmentBuilder.new("Crystal")
        restored.to_s(reprinted, diagnostic_fragment: rebuilder)
        reprinted.to_s.should eq(text)
        rebuilder.finish("recorded", reprinted.to_s).should eq(recorded)
        Iyi::IyiMod.write imported, path
        Iyi::IyiMod.read(path).diagnostic_provenance.not_nil!.fragments[key].anchors.should eq(anchors)
        nested = fragment.anchors.find { |anchor| anchor.kind == "Call" && anchor.role == "method" && anchor.offset != owner.offset }.not_nil!
        {owner, payload, nested}.each do |removed|
          incomplete = fragment.anchors.reject { |anchor| anchor == removed }
          broken = Iyi::Parser.new(carried)
          expect_raises(ArgumentError) do
            broken.diagnostic_regions = [Iyi::DiagnosticRegion.new(0, carried.bytesize, fragment.text_sha256, fragment.events, incomplete)]
            broken.parse
            broken.diagnostic_check_consumed
          end
        end
      end
    end
  end

  it "round trips diagnostic fragments and binds object records to their bytes" do
    source = "-> { 1 }"
    origin = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 8, "ProcLiteral", "arrow")
    fragment = diagnostic_arrow_fragment("mono:f", source, origin)
    object = sample_object_unit
    digest = ::Crystal::Digest::SHA256.hexdigest(object.code)
    section = Iyi::IyiMod::DiagnosticSection.new
    section.add_fragment(fragment)
    section.add_object(Iyi::IyiMod::DiagnosticObjectRecords.new(0, object.name, digest, nil, [] of Iyi::DiagnosticProvenance::Definition))
    decoded = Iyi::IyiMod::DiagnosticSection.decode(section.encode)
    decoded.validate_fragment_keys!(Set{"mono:f"})
    decoded.validate_objects!([object])
    decoded.fragments["mono:f"].anchors.first.origin.should eq(origin)
    expect_raises(ArgumentError) { decoded.validate_fragment_keys!(Set{"mono:other"}) }
    expect_raises(ArgumentError) { decoded.validate_objects!([sample_object_unit("other")]) }

    empty_identity = JSON.parse("{}")
    bad = Iyi::DiagnosticProvenance::Emission.new("requested", "actual", object.name, "external",
      empty_identity, empty_identity, empty_identity, empty_identity)
    bad_definition = Iyi::DiagnosticProvenance::Definition.new(bad, "post", "native", "external", "single")
    expect_raises(Exception) do
      Iyi::IyiMod::DiagnosticSection.new.add_object(
        Iyi::IyiMod::DiagnosticObjectRecords.new(0, object.name, digest, nil, [bad_definition]))
    end
  end

  it "invalidates a cached specialization when visits disagree" do
    definition = Iyi::Def.new("f")
    first = JSON.parse(%({"type":"Int32"}))
    second = JSON.parse(%({"type":"String"}))
    definition.record_diagnostic_specialization(first)
    definition.record_diagnostic_specialization(first)
    definition.diagnostic_specialization_json.should eq(first)
    definition.record_diagnostic_specialization(second)
    definition.diagnostic_specialization_json.should be_nil
    definition.record_diagnostic_specialization(first)
    definition.diagnostic_specialization_json.should be_nil
  end

  it "keeps diagnostic origin out of semantic signature equality" do
    first = signature("f")
    second = signature("f")
    first.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 1, "Def", "keyword")
    second.diagnostic_origin = Iyi::DiagnosticOrigin::Written.new("app", "/a.iyi", 2, "Def", "keyword")
    first.should eq(second)
    Iyi::IyiMod.signature_fragment_key("app", first).should_not eq(Iyi::IyiMod.signature_fragment_key("app", second))
    first.clone.diagnostic_origin.should eq(first.diagnostic_origin)
    first.copy_with(return_type: "Int32").diagnostic_origin.should eq(first.diagnostic_origin)
    first_hashes = Iyi::IyiMod.hashes_for(sample_artifact(exports: [first]), "source")
    second_hashes = Iyi::IyiMod.hashes_for(sample_artifact(exports: [second]), "source")
    first_hashes.interface.should eq(second_hashes.interface)
    first_hashes.implementation.should eq(second_hashes.implementation)
  end

  it "distinguishes concrete and pointer type identities" do
    program = Iyi::Program.new
    integer = Iyi::DiagnosticType.identity(program.int32).not_nil!
    string = Iyi::DiagnosticType.identity(program.string).not_nil!
    pointer = Iyi::DiagnosticType.identity(program.pointer_of(program.int32)).not_nil!
    integer.should_not eq(string)
    pointer.should_not eq(integer)
    pointer["element"].should eq(integer)
  end

  it "removes a stale manifest and rejects a no-codegen request" do
    with_temporary_file do |manifest|
      File.write(manifest, "stale")
      compiler = Iyi::Compiler.new
      compiler.emit_frame_provenance = manifest
      compiler.no_codegen = true
      source = Iyi::Compiler::Source.new("diagnostic-source.iyi", "1")
      expect_raises(Iyi::CompilerError) { compiler.compile(source, "diagnostic-output") }
      File.exists?(manifest).should be_false
    end
  end

  it "does not overwrite an existing link-input proof" do
    with_temporary_file do |proof|
      File.write(proof, "existing")
      compiler = Iyi::Compiler.new
      compiler.emit_link_input_proof = proof
      source = Iyi::Compiler::Source.new("diagnostic-source.iyi", "1")
      expect_raises(Iyi::CompilerError) { compiler.compile(source, "diagnostic-output") }
      File.read(proof).should eq("existing")
    end
  end

  it "rejects missing identity fields and negative offsets" do
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin::Written.new("", "x", 0, "Def", "keyword") }
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin::Written.new("app", "x", -1, "Def", "keyword") }
  end

  it "accepts binding slots only with matching parent anchors" do
    call = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 8, "Call", "method")
    block = Iyi::DiagnosticOrigin::Written.new("app/main", "/src/main.iyi", 20, "Block", "opener")
    Iyi::DiagnosticOrigin::Synthetic.new(call, "local_binding", "assignment").valid_for_binding?.should be_true
    Iyi::DiagnosticOrigin::Synthetic.new(block, "block_parameter", "index:0").valid_for_binding?.should be_true
    Iyi::DiagnosticOrigin::Synthetic.new(block, "block_parameter", "index:00").valid_for_binding?.should be_false
    Iyi::DiagnosticOrigin::Synthetic.new(call, "block_parameter", "index:0").valid_for_binding?.should be_false
  end

  it "rejects truncated or extended origin records" do
    missing = JSON.parse(%({"kind":"Written","source_identity":{"module":"app","file":"x"},"input_byte_offset":0,"anchor_kind":"Def"}))
    extra = JSON.parse(%({"kind":"Synthetic","parent_origin":null,"synthesis_kind":"defer","structural_slot":"cleanup","extra":1}))
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin.from_json(missing) }
    expect_raises(ArgumentError) { Iyi::DiagnosticOrigin.from_json(extra) }
  end
end

# iyi: the `.iyimod` container — SPEC.md IV.1.
#
# The contract these guard is that an artifact is either understood exactly or
# refused. A build cache whose worst case is "read something plausible and
# carried on" is the failure IV.1 is written to avoid, so the rejections below
# matter at least as much as the round trip.

private def sample_artifact(imports = [] of String,
                            exports = [] of Iyi::IyiMod::Signature,
                            types = [] of Iyi::IyiMod::TypeDecl,
                            impls = [] of Iyi::IyiMod::ImplRecord,
                            object_code = [] of Iyi::IyiMod::ObjectUnit,
                            layouts = [] of {String, Iyi::IyiMod::TypeLayout},
                            source_path = "/src/app/greeter.iyi")
  Iyi::IyiMod::Artifact.new(
    module_name: "app/greeter",
    source_path: source_path,
    compiler_version: "1.22.0-dev+abc1234",
    target_triple: "x86_64-pc-linux-gnu",
    flags: ["bits64", "linux"],
    imports: imports.map { |name| Iyi::IyiMod::ImportEdge.new(name) },
    exports: Iyi::IyiMod::Exports.new(exports, types, impls),
    object_code: object_code,
    layouts: layouts,
  )
end

# Not text. An object file holds zero bytes, high bytes and byte sequences that
# are not valid UTF-8, and a container that round-tripped it through a `String`
# would corrupt every one of them — which is why this is the payload the round
# trip below is checked with.
private def sample_object_unit(name : String = "App::Greeter")
  Iyi::IyiMod::ObjectUnit.new(name, Bytes[0x7F, 0x45, 0x4C, 0x46, 0x00, 0xFF, 0x80, 0x00])
end

private def signature(name : String,
                      parameters = [] of String,
                      return_type = "",
                      block_parameter = "",
                      free_variables = [] of String,
                      receiver = "",
                      required = false,
                      free_variable_bounds = [] of {String, String},
                      where_bounds = [] of {String, String})
  Iyi::IyiMod::Signature.new(name, receiver, parameters, block_parameter,
    return_type, free_variables, required,
    free_variable_bounds: free_variable_bounds, where_bounds: where_bounds)
end

private def type_declaration(name : String,
                             kind : String,
                             type_parameters = [] of String,
                             assoc_types = [] of String,
                             supertraits = [] of String,
                             fields = [] of {String, String, String},
                             methods = [] of Iyi::IyiMod::Signature)
  Iyi::IyiMod::TypeDecl.new(name, kind, type_parameters, assoc_types,
    supertraits, fields, methods)
end

private def impl_record(trait_name : String,
                        type_name : String,
                        trait_arguments = [] of String,
                        free_variables = [] of String,
                        free_variable_bounds = [] of {String, String},
                        assoc_types = [] of {String, String},
                        methods = [] of Iyi::IyiMod::Signature)
  Iyi::IyiMod::ImplRecord.new(trait_name, type_name, trait_arguments,
    free_variables, free_variable_bounds, assoc_types, methods)
end

private def with_temporary_file(&)
  path = File.tempname("iyimod", ".iyimod")
  begin
    yield path
  ensure
    File.delete?(path)
  end
end

# Writes *modules* and `main.iyi`, builds the program from source writing the
# modules' artifacts, deletes the modules' sources, builds it again from the
# artifacts and answers what the two programs print. Inside a `with_tempdir`.
private def iyimod_round_trip(modules : Hash(String, String), main : String,
                              release = false) : {String, String}
  modules.each do |path, text|
    Dir.mkdir_p File.dirname(path)
    File.write path, text
  end
  File.write "main.iyi", main
  source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), main)

  producer = create_spec_compiler
  producer.prelude = "iyi/prelude"
  producer.release! if release
  producer.emit_iyimod = "mods"
  producer.compile source, File.expand_path("from-source")
  from_source = `./from-source`

  modules.each_key { |path| File.delete path }

  consumer = create_spec_compiler
  consumer.prelude = "iyi/prelude"
  consumer.release! if release
  consumer.use_iyimod = "mods"
  consumer.compile source, File.expand_path("from-artifact")
  {from_source, `./from-artifact`}
end

describe Iyi::IyiMod do
  # iyi: a `.iyimod` is the one input the compiler reads that nobody typed.
  # Truncated ones used to leave `IO::EOFError` and a stack trace, which names
  # no file and reads as a compiler bug rather than as a damaged file.
  describe "a damaged file" do
    it "is refused rather than crashed on, at every length" do
      with_temporary_file do |path|
        Iyi::IyiMod.write sample_artifact, path
        whole = File.read(path).to_slice

        [1, 8, 64, whole.size // 2, whole.size - 1].each do |cut|
          File.write(path, whole[0, cut])
          expect_raises(Iyi::IyiMod::Error, /#{Regex.escape(path)}/) do
            Iyi::IyiMod.read(path)
          end
          expect_raises(Iyi::IyiMod::Error, /#{Regex.escape(path)}/) do
            Iyi::IyiMod.read_summary(path)
          end
        end
      end
    end

    it "says where it ran out when it ends inside the file" do
      with_temporary_file do |path|
        Iyi::IyiMod.write sample_artifact, path
        whole = File.read(path).to_slice
        File.write(path, whole[0, whole.size - 4])

        # Two wordings, both true: the reader knows it ran out inside a
        # section when the table said how long the section was, and knows only
        # that it ran out when the table itself is short.
        expect_raises(Iyi::IyiMod::Error, /truncated|ends inside/) do
          Iyi::IyiMod.read(path)
        end
      end
    end

    it "refuses a section whose bytes changed under it" do
      # A compiled artifact travels: into a CI cache, over a network, out of a
      # backup. One flipped byte used to build seven times out of ten and reach
      # the linker the other three, which failed without mentioning the file.
      with_temporary_file do |path|
        Iyi::IyiMod.write sample_artifact, path
        bytes = File.read(path).to_slice.dup
        bytes[bytes.size - 3] ^= 0xFF_u8
        File.write(path, bytes)

        expect_raises(Iyi::IyiMod::Error, /damaged|checksum/) do
          Iyi::IyiMod.read(path)
        end
      end
    end

    it "refuses something that was never a .iyimod" do
      with_temporary_file do |path|
        File.write(path, "this is not an artifact\n")
        expect_raises(Iyi::IyiMod::Error, /not a .iyimod|too short/) do
          Iyi::IyiMod.read(path)
        end
      end
    end
  end

  it "round-trips an artifact" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      read = Iyi::IyiMod.read(path)

      read.module_name.should eq "app/greeter"
      read.source_path.should eq "/src/app/greeter.iyi"
      read.compiler_version.should eq "1.22.0-dev+abc1234"
      read.target_triple.should eq "x86_64-pc-linux-gnu"
      read.flags.should eq ["bits64", "linux"]
      read.imports.should be_empty
    end
  end

  it "round-trips intrinsic signature origins and guarded diagnostic sections" do
    with_temporary_file do |path|
      origin = Iyi::DiagnosticOrigin::Written.new("app/greeter", "/src/app/greeter.iyi", 9, "Def", "keyword")
      method = signature("greet")
      method.diagnostic_origin = origin
      artifact = sample_artifact(exports: [method])
      key = Iyi::IyiMod.signature_fragment_key(artifact.module_name, method)
      header = Iyi::IyiMod.render_signature(method)
      section = Iyi::IyiMod::DiagnosticSection.new
      event = Iyi::DiagnosticTokenEvent.new(0, 3, "IDENT", "def", "Iyi", Iyi::DiagnosticTokenSelection::Whole,
        [Iyi::DiagnosticEmissionPart::AstAnchor.new(0, 3, nil, origin)] of Iyi::DiagnosticEmissionPart)
      anchor = Iyi::DiagnosticAnchor.new(0, "Def", "keyword", origin,
        {} of Iyi::DiagnosticNameSlot => Array(Iyi::DiagnosticNameValue), 0, Iyi::DiagnosticFragmentAttachment::Direct.new)
      section.add_fragment(Iyi::IyiMod::DiagnosticFragment.new(key, ::Crystal::Digest::SHA256.hexdigest(header), [event], [anchor]))
      artifact.diagnostic_provenance = section
      Iyi::IyiMod.write artifact, path
      decoded = Iyi::IyiMod.read(path)
      decoded.exports.functions.first.diagnostic_origin.should eq(origin)
      decoded.diagnostic_provenance.not_nil!.fragments[key].anchors.first.origin.should eq(origin)
      decoded.diagnostic_provenance.not_nil!.fragments.delete(key)
      expect_raises(ArgumentError) { Iyi::IyiMod.write decoded, path }
    end
  end

  it "refuses captured artifacts without capture authority on both write and read" do
    with_temporary_file do |path|
      artifact = sample_artifact
      Iyi::IyiMod.write artifact, path
      original = File.read(path).to_slice.dup
      Iyi::IyiMod.read(path).diagnostic_provenance.should be_nil

      artifact.diagnostic_provenance = Iyi::IyiMod::DiagnosticSection.new
      error = expect_raises(Iyi::IyiMod::Error) { Iyi::IyiMod.write artifact, path }
      error.message.should eq("artifact diagnostic capture authority is unavailable")
      File.read(path).to_slice.should eq(original)

      format = Iyi::IyiMod::FORMAT
      count = format.decode(UInt32, original[12, 4])
      table_bytes = count.to_i * 16
      payload = artifact.diagnostic_provenance.not_nil!.encode
      io = IO::Memory.new
      io.write(original[0, 12])
      io.write_bytes(count + 1_u32, format)
      io.write(original[16, table_bytes])
      io.write_bytes(Iyi::IyiMod::Section::DiagnosticProvenance.value, format)
      io.write_bytes(0_u16, format)
      io.write_bytes(payload.size.to_u32, format)
      io.write_bytes(Iyi::IyiMod.checksum(payload), format)
      io.write(original[16 + table_bytes, original.size - 16 - table_bytes])
      io.write(payload)
      File.write(path, io.to_slice)
      error = expect_raises(Iyi::IyiMod::Error) { Iyi::IyiMod.read(path) }
      error.message.should eq("artifact diagnostic capture authority is unavailable")
    end
  end

  it "round-trips import edges in order" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(["std/list", "std/enumerable"]), path
      Iyi::IyiMod.read(path).import_names.should eq ["std/list", "std/enumerable"]
    end
  end

  # A package's own build names its modules under the package's name, and
  # `module app/greeter` alone does not say so (SPEC.md III.7, #132).
  it "round-trips the package name the module's types live under" do
    with_temporary_file do |path|
      artifact = sample_artifact
      Iyi::IyiMod.write artifact, path
      Iyi::IyiMod.read(path).package_name.should eq ""
      Iyi::IyiMod.read_summary(path).package_name.should eq ""
      artifact.package_name = "iyi_web"
      Iyi::IyiMod.write artifact, path
      Iyi::IyiMod.read(path).package_name.should eq "iyi_web"
      Iyi::IyiMod.read_summary(path).package_name.should eq "iyi_web"
    end
  end

  # What each function reaches of module state (SPEC.md III.4.15): absent
  # and empty mean opposite things to a consumer, so both survive the
  # trip, and the record is in the interface hash, since a dependent's
  # spawn placement is compiled from it.
  it "round-trips what each function reaches, absent, empty and recorded" do
    dumped = ->(path : String) do
      io = IO::Memory.new
      Iyi::IyiMod.dump Iyi::IyiMod.read(path), io
      io.to_s
    end
    with_temporary_file do |path|
      artifact = sample_artifact
      Iyi::IyiMod.write artifact, path
      Iyi::IyiMod.read(path).reaches.should be_nil
      dumped.call(path).should contain "reaches       (not recorded)"

      artifact.reaches = [] of Iyi::IyiMod::ReachRecord
      Iyi::IyiMod.write artifact, path
      Iyi::IyiMod.read(path).reaches.should eq [] of Iyi::IyiMod::ReachRecord
      dumped.call(path).should contain "reaches       (nothing unsafe)"
      empty = Iyi::IyiMod.hashes_for(artifact, "").interface

      record = Iyi::IyiMod::ReachRecord.new("App::Greeter#note", "SEEN", "Array(Int32)", "the constant",
        "SEEN.<<", ["helper"], "Array(Int32)'s field @size is assigned in `append`", "app/greeter")
      artifact.reaches = [record]
      Iyi::IyiMod.write artifact, path
      Iyi::IyiMod.read(path).reaches.should eq [record]
      dumped.call(path).should contain \
        "App::Greeter#note reaches the constant `SEEN : Array(Int32)` (module `app/greeter`) through `helper` → `SEEN.<<`"
      Iyi::IyiMod.hashes_for(artifact, "").interface.should_not eq empty
    end
  end

  # Atomic replacement is the property IV.1 picks a single-file container for:
  # a half-written artifact that a later build reads as valid is the worst
  # failure a cache has, because it is wrong and nothing about it looks broken.
  it "leaves no temporary file behind" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      Dir[File.join(File.dirname(path), "#{File.basename(path)}.*.tmp")].should be_empty
    end
  end

  it "refuses a file that is not a .iyimod" do
    with_temporary_file do |path|
      File.write path, "this is not an artifact"
      expect_raises(Iyi::IyiMod::Error, /is not a \.iyimod/) do
        Iyi::IyiMod.read(path)
      end
    end
  end

  it "rejects duplicate section identities before reading payloads" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      bytes = File.read(path).to_slice.dup
      bytes[32, 2].copy_from(bytes[16, 2])
      File.write path, bytes
      expect_raises(Iyi::IyiMod::Error, /duplicate section/) { Iyi::IyiMod.read(path) }
    end
  end

  it "rejects bytes outside the section table" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      File.open(path, "ab") { |file| file.write_byte(0_u8) }
      expect_raises(Iyi::IyiMod::Error, /trailing section bytes/) { Iyi::IyiMod.read(path) }
    end
  end

  it "refuses a file too short to hold the magic" do
    with_temporary_file do |path|
      File.write path, "IYI"
      expect_raises(Iyi::IyiMod::Error, /too short/) do
        Iyi::IyiMod.read(path)
      end
    end
  end

  # IV.5: rejected and rebuilt, never migrated.
  it "refuses another format version" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      bytes = File.read(path).to_slice.dup
      # The version is the u32 right after the 8-byte magic.
      Iyi::IyiMod::FORMAT.encode(99_u32, bytes[8, 4])
      File.write path, bytes

      expect_raises(Iyi::IyiMod::Error, /format v99/) do
        Iyi::IyiMod.read(path)
      end
    end
  end

  it "rejects format v62 rather than guessing provenance" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      bytes = File.read(path).to_slice.dup
      Iyi::IyiMod::FORMAT.encode(62_u32, bytes[8, 4])
      File.write path, bytes
      expect_raises(Iyi::IyiMod::Error, /format v62/) { Iyi::IyiMod.read(path) }
    end
  end
  # The one a v42 artifact in a cache actually hits: the `Layouts` section
  # bumped the format to v43, and the rule above applies to the version this
  # tree wrote yesterday exactly as to one it never wrote.
  it "refuses a v42 artifact" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      bytes = File.read(path).to_slice.dup
      # The version is the u32 right after the 8-byte magic.
      Iyi::IyiMod::FORMAT.encode(42_u32, bytes[8, 4])
      File.write path, bytes

      expect_raises(Iyi::IyiMod::Error, /format v42/) do
        Iyi::IyiMod.read(path)
      end
    end
  end

  # The section table exists so a reader can take what it needs and seek past
  # the rest — that is what will let a consumer read `Exports` without paging in
  # `ObjectCode`. Forward compatibility falls out of the same property, so it is
  # checked here rather than assumed when the later sections arrive.
  it "skips a section it does not know" do
    with_temporary_file do |path|
      io = IO::Memory.new
      format = Iyi::IyiMod::FORMAT
      header = IO::Memory.new
      {"app/greeter", "/src/app/greeter.iyi", "1.0", "triple"}.each do |value|
        header.write_bytes value.bytesize.to_u32, format
        header.write value.to_slice
      end
      header.write_bytes 0_u32, format # no flags
      header.write_byte 0_u8           # no initialiser
      payload = header.to_slice

      unknown = "xyz".to_slice

      io.write Iyi::IyiMod::MAGIC
      io.write_bytes Iyi::IyiMod::FORMAT_VERSION, format
      io.write_bytes 2_u32, format
      io.write_bytes Iyi::IyiMod::Section::Header.value, format
      io.write_bytes 0_u16, format
      io.write_bytes payload.size.to_u32, format
      io.write_bytes Iyi::IyiMod.checksum(payload), format
      io.write_bytes 4242_u16, format # a kind no compiler has ever defined
      io.write_bytes 0_u16, format
      io.write_bytes unknown.size.to_u32, format
      io.write_bytes Iyi::IyiMod.checksum(unknown), format
      io.write payload
      io.write unknown

      File.write path, io.to_slice
      Iyi::IyiMod.read(path).module_name.should eq "app/greeter"
    end
  end

  it "refuses an artifact with no header" do
    with_temporary_file do |path|
      io = IO::Memory.new
      io.write Iyi::IyiMod::MAGIC
      io.write_bytes Iyi::IyiMod::FORMAT_VERSION, Iyi::IyiMod::FORMAT
      io.write_bytes 0_u32, Iyi::IyiMod::FORMAT
      File.write path, io.to_slice

      expect_raises(Iyi::IyiMod::Error, /no header/) do
        Iyi::IyiMod.read(path)
      end
    end
  end

  it "dumps as text" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(["std/list"]), io
    text = io.to_s

    text.should contain "module        app/greeter"
    text.should contain "  std/list"
  end

  # R-2: everything exported carries full parameter and return types, which is
  # why the signature can be the annotation as written rather than a rendering
  # of an inferred type.
  it "round-trips exported signatures" do
    signatures = [
      signature("polite", ["name : String"], "String"),
      signature("title", return_type: "String"),
      signature("pair", ["a : Int32", "b : Array(String)"], "Tuple(Int32, String)"),
    ]

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(exports: signatures), path
      read = Iyi::IyiMod.read(path).exports.functions

      read.size.should eq 3
      read[0].name.should eq "polite"
      read[0].parameters.should eq ["name : String"]
      read[0].return_type.should eq "String"
      read[1].parameters.should be_empty
      read[2].parameters.should eq ["a : Int32", "b : Array(String)"]
      read[2].return_type.should eq "Tuple(Int32, String)"
    end
  end

  # Everything a consumer needs and the source's `def` line carries. Each of
  # these was absent from the format until a consumer that reads the artifact
  # instead of the source went looking for it: without the block annotation
  # there is no `yield` left to infer a block from, without the `forall` the
  # return type does not resolve, and an `abstract def` read as a definition is
  # a requirement nobody is told they missed.
  it "round-trips the rest of a def's header" do
    signatures = [
      signature("map", ["a : Int32"], "Array(U)",
        block_parameter: "& : (Elem -> U)", free_variables: ["U"]),
      signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true),
      signature("zero", return_type: "self", receiver: "self"),
      signature("push", ["*values : T", "**options"]),
    ]

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(exports: signatures), path
      read = Iyi::IyiMod.read(path).exports.functions

      read[0].block_parameter.should eq "& : (Elem -> U)"
      read[0].free_variables.should eq ["U"]
      read[0].required.should be_false
      read[1].required.should be_true
      read[2].receiver.should eq "self"
      read[3].parameters.should eq ["*values : T", "**options"]
    end
  end

  # A bound is checked where a call matches (II.6 §3), so a consumer that
  # has only the artifact needs it as much as the names. The format carried
  # `forall T` for `forall T : Show` and nothing for `where Elem : Show`, and
  # a consumer accepted calls the source build refused.
  it "round-trips and renders a def's bounds" do
    signatures = [
      signature("render", ["x : T", "y : U"], "String", free_variables: ["T", "U"],
        free_variable_bounds: [{"T", "Show"}]),
      signature("shown", return_type: "String", where_bounds: [{"Elem", "Show"}, {"Key", "Cmp"}]),
    ]

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(exports: signatures), path
      read = Iyi::IyiMod.read(path).exports.functions

      Iyi::IyiMod.render_signature(read[0]).should eq "def render(x : T, y : U) : String forall T : Show, U"
      Iyi::IyiMod.render_signature(read[1]).should eq "def shown : String where Elem : Show, Key : Cmp"
    end
  end

  it "observes exact signature field byte spans without changing the rendering" do
    signature = Iyi::IyiMod::Signature.new("render", "self", ["x : T", "label = \"é\""], "&block : Proc",
      "String", ["T", "U"], true, visibility: "private",
      free_variable_bounds: [{"T", "Show"}], where_bounds: [{"T", "Trait"}])
    expected = "private abstract def self.render(x : T, label = \"é\", &block : Proc) : String forall T : Show, U where T : Trait"
    text, fields = Iyi::IyiMod.render_signature_observed(signature)
    text.should eq(expected)
    Iyi::IyiMod.render_signature(signature).should eq(expected)
    fields.each do |field|
      text.byte_slice(field.start_offset, field.end_offset - field.start_offset).should eq(field.text)
    end
    fields.map { |field| {field.kind, field.index, field.text} }.should eq([
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Visibility, -1, "private"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Abstract, -1, "abstract"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Def, -1, "def"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Receiver, -1, "self"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Name, -1, "render"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 0, "x : T"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::Parameter, 1, "label = \"é\""},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::BlockParameter, -1, "&block : Proc"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::ReturnType, -1, "String"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::ForallName, 0, "T"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::ForallBound, 0, "Show"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::ForallName, 1, "U"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::WhereName, 0, "T"},
      {Iyi::IyiMod::DiagnosticSignatureFieldKind::WhereBound, 0, "Trait"},
    ])
    sink = NonPositionableDiagnosticIO.new
    Iyi::IyiMod.write_signature(sink, signature)
    sink.buffer.to_s.should eq(expected)
    observer = ->(_field : Iyi::IyiMod::DiagnosticSignatureFieldWrite) { nil }
    expect_raises(ArgumentError) { Iyi::IyiMod.write_signature(NonPositionableDiagnosticIO.new, signature, observer) }
  end

  it "rejects changed signature fields without an authoritative projection recipe" do
    definition = captured_diagnostic_def("def greet(x : String) : String\nend", "/absent/header.cr", "Crystal")
    signature = Iyi::IyiMod.signature(definition, check_block: false)
    changed = signature.copy_with(return_type: "Int32")
    expect_raises(ArgumentError, /signature field differs from source AST/) do
      Iyi::IyiMod.diagnostic_signature_fragment("app", definition, changed, "Crystal")
    end
  end

  it "captures signature recipes from real arguments and rejects unvalidated bound changes" do
    definition = captured_diagnostic_def("def f(x : Int32 = 1, *rest : String)\nend", "/absent/recipe.cr", "Crystal")
    signature = Iyi::IyiMod.signature(definition, check_block: false)
    recipe = Iyi::IyiMod::DiagnosticSignatureRecipe.from_def(definition, signature)
    recipe.parameters.map(&.kind).should eq([Iyi::IyiMod::DiagnosticSignatureParameterKind::Normal,
                                             Iyi::IyiMod::DiagnosticSignatureParameterKind::Splat])
    recipe.parameters.map(&.name_text).should eq(["x", "*rest"])
    recipe.parameters.first.restriction_text.should eq("Int32")
    recipe.parameters.first.default_text.should eq("1")
    recipe.parameters.clear
    recipe.parameters.size.should eq(2)
    argument = definition.args.first
    bad = Iyi::IyiMod::DiagnosticSignatureParameterRecipe.new(argument,
      Iyi::IyiMod::DiagnosticSignatureParameterKind::Normal, "x", "Other", "1",
      [Iyi::DiagnosticBoundProducer::StripRoot.new("Root")] of Iyi::DiagnosticBoundProducer,
      [] of Iyi::DiagnosticBoundProducer, false)
    rest = Iyi::IyiMod::DiagnosticSignatureParameterRecipe.new(definition.args.last,
      Iyi::IyiMod::DiagnosticSignatureParameterKind::Splat, "*rest", "String", nil,
      [] of Iyi::DiagnosticBoundProducer, [] of Iyi::DiagnosticBoundProducer, false)
    changed = signature.copy_with(parameters: ["x : Other = 1", "*rest : String"])
    expect_raises(ArgumentError, /authoritative source validation/) do
      Iyi::IyiMod::DiagnosticSignatureRecipe.from_bind(definition, changed, [bad, rest], nil, [] of Iyi::DiagnosticBoundProducer)
    end
  end

  it "dumps a def's header the way it was written" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(exports: [
      signature("map", ["a : Int32"], "Array(U)",
        block_parameter: "& : (Elem -> U)", free_variables: ["U"]),
      signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true),
      signature("zero", return_type: "self", receiver: "self"),
    ]), io
    text = io.to_s

    text.should contain "  def map(a : Int32, & : (Elem -> U)) : Array(U) forall U"
    # A block parameter alone still gets the parentheses it needs.
    text.should contain "  abstract def each(& : (Elem -> Nil)) : Nil"
    text.should contain "  def self.zero : self"
  end

  it "dumps a signature the way it was written" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(exports: [
      signature("polite", ["name : String"], "String"),
      signature("title", return_type: "String"),
    ]), io
    text = io.to_s

    text.should contain "  def polite(name : String) : String"
    # No empty parens for a function that takes nothing.
    text.should contain "  def title : String"
  end

  # The format still stops short of what codegen needs, and a reader has no way
  # to tell an absent field list from an empty one, so the dump says so.
  # For a long time this note said what the format was still missing, because a
  # reader has no way to tell an absent field list from an empty one. Every
  # section the enum names is written now, so it says what is in the file.
  it "says what the format carries" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact, io
    text = io.to_s
    text.should contain "carries declarations"
    text.should contain "the macros"
    text.should contain "bodies a consumer has to compile for itself"
  end

  it "round-trips object code byte for byte" do
    unit = sample_object_unit
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(object_code: [unit]), path
      read = Iyi::IyiMod.read(path, want_object_code: true).object_code

      read.size.should eq 1
      read.first.name.should eq "App::Greeter"
      read.first.code.should eq unit.code
    end
  end

  it "round-trips one unit per type, in order" do
    units = [sample_object_unit("App::Greeter"), sample_object_unit("App::Greeter::Formal")]
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(object_code: units), path
      read = Iyi::IyiMod.read(path, want_object_code: true).object_code
      read.map(&.name).should eq ["App::Greeter", "App::Greeter::Formal"]
    end
  end

  # The reader that matters most is `import`, and it is a front-end reader: it
  # wants the declarations and has no use for the machine code. Reading the
  # largest section in the file anyway would put it on the path of the pass the
  # artifact exists to make fast, so it is seeked past unless asked for.
  it "does not read object code unless asked" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(object_code: [sample_object_unit]), path

      Iyi::IyiMod.read(path).object_code.should be_empty
      Iyi::IyiMod.read(path, want_object_code: true).object_code.size.should eq 1
    end
  end

  # Seeking past a section only works if what follows it is still found, so the
  # skip is checked by reading something written *after* the object code — the
  # exports, which the writer puts before it, and the header, which it puts
  # first. A skip of the wrong length would lose both.
  it "reads the rest of the file with the object code skipped" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(imports: ["std/list"],
        exports: [signature("polite", ["name : String"], "String")],
        object_code: [sample_object_unit]), path

      read = Iyi::IyiMod.read(path)
      read.module_name.should eq "app/greeter"
      read.import_names.should eq ["std/list"]
      read.exports.functions.map(&.name).should eq ["polite"]
    end
  end

  # A `--no-codegen` build writes an artifact with nothing to link. The section
  # is left out rather than written empty, so that such a file is the same size
  # it was before this section existed.
  it "omits the object code section when there is none" do
    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact, path
      # Section count is the u32 after the 8-byte magic and the version.
      count = Iyi::IyiMod::FORMAT.decode(UInt32, File.read(path).to_slice[12, 4])
      count.should eq 3
    end
  end

  it "dumps the units it carries, and says when it carries none" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(object_code: [sample_object_unit]), io
    io.to_s.should contain "App::Greeter — 8 bytes"

    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact, io
    io.to_s.should contain "object code   (none)"
  end

  # The only example here that compiles a real program, and the one thing the
  # container specs above cannot check: that the name a unit is filed under is
  # the name codegen gave it. Codegen emits one object file per owner type and
  # names it after that type; an artifact that agreed on the bytes and not on
  # the name would carry machine code nobody could match to a declaration.
  it "carries the object code of a module's own type" do
    with_tempdir("iyimod_object_code") do
      Dir.mkdir_p "app"
      File.write "app/greeter.iyi", <<-IYI
        module app/greeter

        pub def polite(name : String) : String
          "Hello, " + name
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/greeter

        puts App::Greeter.polite("world")
        IYI

      compiler = create_spec_compiler
      # Chosen by the entry file's extension in `crystal build`, which is the
      # command layer rather than the compiler, so a spec driving the compiler
      # directly asks for it.
      compiler.prelude = "iyi/prelude"
      compiler.emit_iyimod = "mods"

      with_temp_executable("iyimod-object-code") do |executable|
        source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
        compiler.compile source, executable
      end

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "greeter.iyimod"),
        want_object_code: true)
      unit = artifact.object_code.find { |candidate| candidate.name == "App::Greeter" }
      unit.should_not be_nil
      unit.not_nil!.code.should_not be_empty
    end
  end

  # The claim Part IV exists for, end to end: a program built from a module's
  # artifact, with the module's source **deleted**, that runs and prints what
  # the same program printed when it was built from source.
  #
  # The module is arithmetic on purpose: everything it calls is a primitive, so
  # this example is about the mechanism and nothing else. The example after it
  # is the one that needs the closure.
  it "builds and runs a program from a module's artifact, source deleted" do
    with_tempdir("iyimod_end_to_end") do
      Dir.mkdir_p "app"
      File.write "app/twice.iyi", <<-IYI
        module app/twice

        pub def twice(n : Int32) : Int32
          n + n
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/twice

        puts App::Twice.twice(21)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      File.delete "app/twice.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "42"
    end
  end

  it "adopts std/env artifact with operator effect defs under observed and plain builds" do
    with_tempdir("iyimod_env_operator_effects") do
      var_name = "IYI_SPEC_ENV_#{Process.pid}"
      File.write "main.iyi", <<-IYI
        module main

        import app/twice
        import std/env::{ENV}

        ENV["#{var_name}"] = "set"
        puts ENV["#{var_name}"]?.inspect
        ENV["#{var_name}"] = nil
        puts ENV["#{var_name}"]?.inspect
        puts App::Twice.twice(21)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected_output = %("set"\nnil\n42\n)

      [true, false].each do |observed|
        mode = observed ? "observed" : "plain"
        mods_dir = "mods-#{mode}"

        Dir.mkdir_p "app"
        File.write "app/twice.iyi", <<-IYI
          module app/twice

          pub def twice(n : Int32) : Int32
            n + n
          end
          IYI

        producer = create_spec_compiler
        producer.prelude = "iyi/prelude"
        producer.emit_iyimod = mods_dir
        producer.flags << "iyi_observe" if observed
        producer.compile source, File.expand_path("from-source-#{mode}")
        source_output = `./from-source-#{mode}`
        source_output.should eq expected_output

        File.delete "app/twice.iyi"

        consumer = create_spec_compiler
        consumer.prelude = "iyi/prelude"
        consumer.use_iyimod = mods_dir
        consumer.flags << "iyi_observe" if observed
        result = consumer.compile source, File.expand_path("from-artifact-#{mode}")
        result.program.iyi_artifact_hashes.has_key?("std/env").should be_true
        artifact_output = `./from-artifact-#{mode}`
        artifact_output.should eq source_output
      end
    end
  end

  # An exported `enum`, which travels as its members and the numbers they were
  # given. Three things were in the way, each invisible until one was exported:
  # the question methods the compiler writes carried no return type, so R-2
  # refused the module ("`debug?` is exported and does not say what it
  # returns"); the writer asked the enum for its instance variables (`BUG:
  # Level::Level doesn't implement instance_vars`); and its members read as
  # code inside a type body, so the artifact could not be imported at all.
  #
  # The surface is not carried and must not be: `value`, `new` and a question
  # method per member are the consumer's compiler's to write from this
  # declaration, and `==`, `to_s` and the rest are the prelude's `Enum`.
  it "builds and runs a program from a module's exported enum" do
    with_tempdir("iyimod_enum") do
      Dir.mkdir_p "app"
      File.write "app/levels.iyi", <<-IYI
        module app/levels

        pub enum Level : Int32
          Debug = 0
          Warn  = 2
        end

        @[Flags]
        pub enum Mode
          Read
          Write
          Append
        end

        pub def loudest : Level
          Level::Warn
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/levels::{Level, Mode, loudest}

        puts "\#{loudest} \#{loudest == Level::Warn} \#{loudest.warn?} \#{Level.values.size} \#{(Mode::Read | Mode::Write)}"
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "Warn true true 2 Read | Write"

      # The declaration carries the members and their numbers, and not the
      # `None` and `All` a `@[Flags]` enum is given wherever it is declared —
      # carried, they arrive as a redefinition of the consumer's own.
      artifact = Iyi::IyiMod.read(File.join("mods", "app", "levels.iyimod"))
      level = artifact.exports.types.find { |declaration| declaration.name == "Level" }
      level.should_not be_nil
      level.not_nil!.kind.should eq "enum"
      level.not_nil!.value.should eq "Int32"
      level.not_nil!.members.should eq [{"Debug", "0"}, {"Warn", "2"}]
      mode = artifact.exports.types.find { |declaration| declaration.name == "Mode" }
      mode.not_nil!.annotations.should eq ["@[Flags]"]
      mode.not_nil!.members.map(&.[0]).should eq ["Read", "Write", "Append"]

      File.delete "app/levels.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "Warn true true 2 Read | Write"
    end
  end

  # A generic the consumer instantiates, which is the one type an artifact
  # carries no object code for.
  #
  # `collect_iyi_unit_names` gives a module's object code a unit per non-generic
  # type it declares and none for a generic one, because a generic has machine
  # code only once somebody picks its arguments. The consumer is who picks them
  # here, so `Box(Int32)`'s methods are the consumer's to compile — and the
  # marking that says "this type's code is in the artifact" was reading the
  # generic itself, which made the consumer declare a `new` nobody defined.
  #
  # Written twice on purpose. `Box(Int32).new` is owned by the instance, which
  # was never marked and always worked; `Box.new(42)` infers the argument, and
  # inference makes `new` a method on `Box(T)` — the artifact's own type. Only
  # the second one linked undefined, so only the second one is the regression.
  it "builds a generic from an artifact whether or not its argument is written" do
    with_tempdir("iyimod_generic_instance") do
      Dir.mkdir_p "app"
      File.write "app/boxes.iyi", <<-IYI
        module app/boxes

        pub struct Box(T)
          getter value : T

          def initialize(@value : T)
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/boxes

        written = App::Boxes::Box(Int32).new(21)
        inferred = App::Boxes::Box.new(21)
        puts written.value + inferred.value
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      File.delete "app/boxes.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "42"
    end
  end

  # The closure (IV.1g): the module's body calls `String#+`, which lives in the
  # prelude's `String` unit — a unit the artifact does not carry and one whose
  # contents on the consumer's side are whatever *the consumer* instantiated.
  # The consumer here never writes a `+`, so nothing would define it, and this
  # is the build that failed to link before the module started carrying private
  # copies of what it calls.
  it "carries what a module's body calls but its consumer does not" do
    with_tempdir("iyimod_closure") do
      Dir.mkdir_p "app"
      File.write "app/greeter.iyi", <<-IYI
        module app/greeter

        pub def polite(name : String) : String
          "Hello, " + name
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/greeter

        puts App::Greeter.polite("world")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "Hello, world"

      File.delete "app/greeter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "Hello, world"
    end
  end

  # A type id is an external reference, which is what lets one build's object
  # file be linked by another's — and the definition comes from the consuming
  # program, which defines an id for every type it *has*. `Array(Item)` is not
  # one of them: it exists in the producing build because of a body that stays
  # behind, and nothing in the declarations the consumer reads would ever make
  # it. So `Array(App::Box::Item):type_id` was undefined at link, in a program
  # whose every method resolved.
  it "numbers the types a module's own code instantiates" do
    with_tempdir("iyimod_type_ids") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        pub struct Item
          @name : String

          def initialize(@name : String)
          end

          def name : String
            @name
          end
        end

        pub def labels : String
          items = Array(Item).new
          items << Item.new("a")
          items << Item.new("b")
          items.map { |item| item.name }.join(", ")
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.labels
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "a, b"

      # The instantiation the consumer cannot reach any other way, named in the
      # artifact so that it can make it.
      artifact = Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod"))
      artifact.type_ids.should contain "Array(App::Box::Item)"

      File.delete "app/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "a, b"
    end
  end

  # A type the module keeps to itself still has to arrive, because its object
  # code refers to it: `Array(Secret):type_id` is resolved from a definition in
  # this program and a program can only number a type it has. So it travels as
  # a declaration without `pub` — reachable from nowhere, which is exactly what
  # it is when the module is read from source.
  it "carries a type its module does not export" do
    with_tempdir("iyimod_type_ids_private") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        struct Secret
          @n : Int32

          def initialize(@n : Int32)
          end

          def n : Int32
            @n
          end
        end

        pub def total : Int32
          items = Array(Secret).new
          items << Secret.new(2)
          items << Secret.new(3)
          items[0].n + items[1].n
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.total
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "5"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod"))
      secret = artifact.exports.types.find! { |declaration| declaration.name == "Secret" }
      secret.visibility.should eq "private"
      secret.fields.should eq [{"@n", "::Int32", ""}]
      # Headers, and only headers. The consumer cannot reach them and the
      # module's own object code already defines them — but a body that
      # travels calls them, and a call it cannot typecheck is refused before
      # anything gets as far as being unreachable.
      secret.methods.map(&.name).sort!.should eq ["initialize", "n"]
      secret.methods.each { |signature| signature.required.should be_false }

      File.delete "app/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "5"

      # And carrying it does not make it reachable, which is the half R-2b is
      # about: the consumer has the type and may not name it.
      File.write "reach.iyi", <<-IYI
        module main

        import app/box

        puts App::Box::Secret.new(1).n
        IYI
      reaching = Iyi::Compiler::Source.new(File.expand_path("reach.iyi"), File.read("reach.iyi"))

      refuser = create_spec_compiler
      refuser.prelude = "iyi/prelude"
      refuser.use_iyimod = "mods"
      refuser.no_codegen = true
      expect_raises(Iyi::TypeException, /does not export App::Box::Secret/) do
        refuser.compile reaching, "unused"
      end
    end
  end

  # R-3 says there are no open classes, and the way somebody reaches for one is
  # a qualified declaration: `struct App::A::Point` inside their own module.
  # Crystal reads that as reopening. iyi cannot, so it used to create a second
  # `Point` under `Main::App::A` and fail later with `wrong number of arguments
  # for 'Main::App::A::Point.new'`, which names neither the rule nor the type
  # the author meant.
  it "refuses a declaration that adds to another module's namespace" do
    with_tempdir("iyi_r3_reopen") do
      Dir.mkdir_p "app"
      File.write "app/a.iyi", <<-IYI
        module app/a

        pub struct Point
          getter x : Int32

          def initialize(@x : Int32)
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/a

        struct App::A::Point
          def doubled : Int32
            x * 2
          end
        end

        puts App::A::Point.new(2).doubled
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      compiler = create_spec_compiler
      compiler.prelude = "iyi/prelude"
      compiler.no_codegen = true
      expect_raises(Iyi::TypeException, /`App::A::Point` already exists.*cannot add to it/m) do
        compiler.compile source, "unused"
      end

      # A file's own namespace is its own to declare into, and two modules
      # under `app/` share `App` by design: neither is reopening.
      File.write "main.iyi", <<-IYI
        module main

        import app/a

        module Helpers
        end

        struct Helpers::Thing
          def n : Int32
            7
          end
        end

        puts Helpers::Thing.new.n + App::A::Point.new(2).x
        IYI
      allowed = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      ok = create_spec_compiler
      ok.prelude = "iyi/prelude"
      ok.compile allowed, File.expand_path("allowed")
      `./allowed`.chomp.should eq "9"
    end
  end

  # R-2 was a rule the format assumed and nothing checked, and the cost of that
  # landed on the consumer: `pub def greet(name)` compiled, the artifact
  # recorded `def greet(name)`, and a build reading it typed the call from a
  # return type that was not there. The producer emitted `greet<String>:String`
  # and the consumer asked the linker for `greet<String>:Nil`.
  it "refuses an exported def that does not write its types down" do
    with_tempdir("iyimod_r2") do
      Dir.mkdir_p "app"
      File.write "main.iyi", <<-IYI
        module main

        import app/a

        puts App::A.greet("x")
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      write = ->(body : String) do
        File.write "app/a.iyi", "module app/a\n\n#{body}\n"
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.emit_iyimod = "mods"
        compiler.no_codegen = true
        compiler
      end

      expect_raises(Iyi::TypeException, /`greet` is exported and does not say what `name` is/) do
        write.call("pub def greet(name)\n  \"hi \#{name}\"\nend").compile source, "unused"
      end

      expect_raises(Iyi::TypeException, /`greet` is exported and does not say what it returns/) do
        write.call("pub def greet(name : String)\n  \"hi \#{name}\"\nend").compile source, "unused"
      end

      # Written down, and the same program builds from the artifact and prints
      # what the build from source prints.
      compiler = write.call("pub def greet(name : String) : String\n  \"hi \#{name}\"\nend")
      compiler.no_codegen = false
      compiler.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "hi x"

      File.delete "app/a.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "hi x"
    end
  end

  # A method that takes a block is instantiated with the caller's block inlined
  # into it, so its machine code belongs to whoever wrote the block. The
  # producer emits none — it would be a duplicate for a block it happened to
  # write and missing for every block it did not — and the body travels instead,
  # for the reason a generic's method and a trait's default do (SPEC.md IV.1g).
  it "carries the body of a method that takes a block" do
    with_tempdir("iyimod_block_bodies") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        pub class Box
          alias Step = Int32 -> Int32

          private record Entry,
            step : Step

          getter label : String
          @entries : Array(Entry)

          def initialize(@label : String)
            @entries = [] of Entry
          end

          def add(&block : Int32 -> Int32) : Nil
            @entries << Entry.new(step: block)
          end

          def run(start : Int32) : Int32
            total = start
            @entries.each { |entry| total = entry.step.call(total) }
            total
          end
        end

        pub def boxed(label : String, &block : Int32 -> Int32) : Box
          box = Box.new(label)
          box.add(&block)
          box
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        box = App::Box.boxed("doubling") { |n| n * 2 }
        box.add { |n| n + 1 }
        puts box.label
        puts box.run(5)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "doubling\n11"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod"))

      # Whatever the def is written on: a module's own `pub def` and a method
      # of an exported class are the same case.
      artifact.mono_bodies.keys.should contain "app/box#boxed(label : String)&block : (Int32 -> Int32)"
      artifact.mono_bodies.keys.should contain "Box#add()&block : (Int32 -> Int32)"

      box = artifact.exports.types.find! { |declaration| declaration.name == "Box" }

      # Declaration order, because it is the layout the consumer's copy of
      # `add` writes `@entries` at and the module's own `run` reads it from.
      box.fields.map { |(name, _, _)| name }.should eq ["@label", "@entries"]

      # The alias travels because a declaration that travels names it: the
      # carried record's `step : Step` is the text this module was written
      # with, and a consumer without the alias reads an undefined constant.
      #
      # As written, not as resolved — `it "carries an alias as the module
      # wrote it"` is why, and `Proc(Int32, Int32)` is what this used to say.
      step = box.types.find! { |nested| nested.name == "Step" }
      step.kind.should eq "alias"
      step.value.should eq "(Int32 -> Int32)"

      File.delete "app/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "doubling\n11"
    end
  end

  # A body that travels calls what the module keeps to itself, and being
  # unreachable does not change who compiles a block-taking def. Both shapes
  # are here because they are one hole seen in two namespaces: a method on a
  # type the module does not export, and a def at the module's own top level.
  it "carries the unexported defs a travelling body calls" do
    with_tempdir("iyimod_carried_defs") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        class Hidden
          @n : Int32

          def initialize(@n : Int32)
          end

          def tweak(&block : Int32 -> Int32) : Int32
            block.call(@n)
          end
        end

        def helper(start : Int32, &block : Int32 -> Int32) : Int32
          Hidden.new(start).tweak(&block)
        end

        pub def run(start : Int32, &block : Int32 -> Int32) : Int32
          helper(start, &block)
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.run(5) { |n| n * 3 }
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "15"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod"))

      # Kept out of `functions`, which is the module's surface and stays what a
      # consumer may call.
      artifact.exports.functions.map(&.name).should eq ["run"]
      artifact.exports.carried_functions.map(&.name).should eq ["helper"]

      # With their bodies, because a header would promise a symbol the producer
      # never emitted: it makes no machine code for a block-taking def either.
      artifact.mono_bodies.keys.should contain "app/box#helper(start : Int32)&block : (Int32 -> Int32)"
      artifact.mono_bodies.keys.should contain "Hidden#tweak()&block : (Int32 -> Int32)"

      File.delete "app/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "15"

      # And carrying them leaves R-2b where it was: the consumer has them and
      # may not name them, with the message it gets from source.
      File.write "reach.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.helper(5) { |n| n * 3 }
        IYI
      reaching = Iyi::Compiler::Source.new(File.expand_path("reach.iyi"), File.read("reach.iyi"))

      refuser = create_spec_compiler
      refuser.prelude = "iyi/prelude"
      refuser.use_iyimod = "mods"
      refuser.no_codegen = true
      expect_raises(Iyi::TypeException, /does not export 'helper'/) do
        refuser.compile reaching, "unused"
      end
    end
  end

  # A macro has no machine code to arrive as and no `pub` to be exported with,
  # and a body that travels calls one: the consumer compiles `run`, `run`
  # writes `twice(n)`, and `twice` is a macro of the module `run` came from.
  # Both places one can be written are here, because they are one rule.
  it "carries the macros a travelling body expands" do
    with_tempdir("iyimod_macro_bodies") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        macro twice(x)
          ({{x}} + {{x}})
        end

        pub class Box
          macro double(x)
            ({{x}} * 2)
          end

          @n : Int32

          def initialize(@n : Int32)
          end

          def run(&block : Int32 -> Int32) : Int32
            block.call(double(@n))
          end
        end

        pub def run_module(n : Int32, &block : Int32 -> Int32) : Int32
          block.call(twice(n))
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box::Box.new(5).run { |n| n + 1 }
        puts App::Box.run_module(5) { |n| n + 1 }
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "11\n11"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod"))
      artifact.macro_bodies.size.should eq 1
      artifact.macro_bodies.first.should start_with "macro twice"

      # On the type it was declared on, because that is where it is looked up.
      box = artifact.exports.types.find! { |declaration| declaration.name == "Box" }
      box.macros.size.should eq 1
      box.macros.first.should start_with "macro double"

      File.delete "app/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "11\n11"
    end
  end

  # An error in the declarations has a location in them, and the file that
  # location names is binary — so the line it showed was the bytes of the
  # container the declarations travelled in. The text is what the build read
  # and the text is what it shows. In a travelling body the location is the
  # module's source, and with the source gone the line still comes from the
  # text the artifact carried (issue #140).
  it "shows the declaration an error is in, not the bytes of the artifact" do
    with_tempdir("iyimod_error_source") do
      Dir.mkdir_p "app"
      # A generic's body travels and the consumer instantiates it, so a type
      # the producer never tried is where this lands: the error is in a line of
      # the module's, reported to somebody who does not have the module.
      File.write "app/box.iyi", <<-IYI
        module app/box

        pub struct Box(T)
          @item : T

          def initialize(@item : T)
          end

          def doubled : T
            @item + @item
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box::Box(Int32).new(21).doubled
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      File.delete "app/box.iyi"

      File.write "bad.iyi", <<-IYI
        module main

        import app/box

        puts App::Box::Box(Bool).new(true).doubled
        IYI
      bad = Iyi::Compiler::Source.new(File.expand_path("bad.iyi"), File.read("bad.iyi"))

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.no_codegen = true

      error = expect_raises(Iyi::TypeException, /undefined method '\+' for Bool/) do
        consumer.compile bad, File.expand_path("unused")
      end

      rendered = error.to_s
      rendered.should contain "@item + @item"
      # The source's path as the source build spells it: `app\box.iyi` on
      # Windows, where the first Windows run of this held it to `/`.
      rendered.should contain "#{Path["app", "box.iyi"]}:10:11"
      # The bytes the artifact starts with, which is what used to be shown.
      rendered.should_not contain "IYIMOD"
    end
  end

  # A class variable is a global, and its global is defined in the main module
  # — the one part of a build that never travels. The methods that read one
  # travel as this module's machine code referring to it by symbol, so a module
  # with a `@@seen` failed R-1's own round trip on
  # `undefined symbol: App::Counter::Tally::seen`, and this file's own gate for
  # that claim passed because no sample had a class variable.
  #
  # Two of them, and the nilable one is not decoration. `@@cache : String? = nil`
  # has its initialiser dropped before an artifact is written — assigning nil
  # assigns nothing — so the declaration travelling is not enough on its own:
  # the consumer read it, made no initialiser from it, and codegen emitted no
  # global. The name travelling in `ClassVars` is what closes that half.
  it "carries a module's class variables, declaration and global" do
    with_tempdir("iyimod_class_vars") do
      Dir.mkdir_p "app"
      File.write "app/counter.iyi", <<-IYI
        module app/counter

        pub struct Tally
          @@cache : String? = nil
          @@seen : Int32 = 0

          def initialize
          end

          pub def remember(s : String) : String
            @@cache = s
            @@seen = @@seen + 1
            (@@cache || "none") + ":" + @@seen.to_s
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/counter

        t = App::Counter::Tally.new
        puts t.remember("hello")
        puts t.remember("again")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "hello:1\nagain:2"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "counter.iyimod"))
      # The module's own two, plus the scheduler's: `raise` reaches the
      # panic path now (III.1.4), so every unit's object code refers to
      # the runtime's globals — the same rule that carries
      # `Unicode::@@upcase_ranges` for a shard that calls `upcase`, and
      # the consumer emits them once either way.
      artifact.class_vars.map(&.name).select(&.starts_with?("App::")).should eq [
        "App::Counter::Tally::@@cache",
        "App::Counter::Tally::@@seen",
      ]
      artifact.class_vars.map(&.name).any?(&.starts_with?("IyiScheduler::")).should be_true

      # None of them lazy, and that is a fact about the prelude rather than
      # about these two: iyi's has no `__crystal_once`, so a unit under it
      # never reads a class variable through an init flag.
      artifact.class_vars.map(&.lazy).uniq.should eq [false]

      tally = artifact.exports.types.find { |type| type.name == "Tally" }.should_not be_nil
      tally.class_vars.map { |class_var| {class_var.name, class_var.type, class_var.value} }
        .should eq [{"@@cache", "(::String | ::Nil)", ""}, {"@@seen", "::Int32", "0"}]
      tally.class_vars.map(&.annotations).should eq [[] of String, [] of String]

      File.delete "app/counter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "hello:1\nagain:2"
    end
  end

  # A constant is typed and initialised where it is *read*, and on the far side
  # of an artifact the only reader is machine code the consumer did not compile.
  # So `kemal/dsl`'s `APP` was declared, assigned by the initialiser that
  # travelled, and never given a symbol — every exported method in the unit
  # called through a global nothing defined.
  it "carries the constants a module's own code reads" do
    with_tempdir("iyimod_constants") do
      Dir.mkdir_p "app"
      File.write "app/counter.iyi", <<-IYI
        module app/counter

        pub struct Tally
          @n : Int32

          def initialize(@n : Int32)
          end

          def n : Int32
            @n
          end
        end

        START = Tally.new(40)

        pub def total : Int32
          START.n + 2
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/counter

        puts App::Counter.total
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "counter.iyimod"))
      artifact.constants.should eq ["App::Counter::START"]

      File.delete "app/counter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "42"
    end
  end

  # The router's shape: a `private record` inside an exported class. It belongs
  # to the class rather than to the module's surface — R-2 governs the unit's
  # own body — so it travels inside its container, and the field that names it
  # travels with the name it was written with.
  it "carries a type declared inside a carried type" do
    with_tempdir("iyimod_nested_types") do
      Dir.mkdir_p "app"
      File.write "app/router.iyi", <<-IYI
        module app/router

        pub class Router
          private struct Route
            @method : String
            @path : String

            def initialize(@method : String, @path : String)
            end
          end

          @routes : Array(Route)

          def initialize
            @routes = Array(Route).new
          end

          pub def add(method : String, path : String) : Nil
            @routes << Route.new(method, path)
          end

          pub def count : Int32
            @routes.size
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/router

        router = App::Router::Router.new
        router.add("GET", "/")
        router.add("POST", "/x")
        puts router.count
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "2"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "router.iyimod"))
      router = artifact.exports.types.find! { |declaration| declaration.name == "Router" }
      route = router.types.find! { |declaration| declaration.name == "Route" }
      route.visibility.should eq "private"

      # Rendered where it was written, because iyi cannot reopen `Router` to
      # add it afterwards.
      io = IO::Memory.new
      Iyi::IyiMod.declarations artifact, io
      io.to_s.should contain "  private struct Route"

      File.delete "app/router.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "2"
    end
  end

  # A class method lives on the type's *metaclass*, so walking a type's own
  # defs dropped every one a module exported — `Counter.zero` was an undefined
  # method on the far side of an artifact that looked complete. And a field
  # with a bodyless `initialize` is the shape no sample has: the artifact's
  # `initialize` has no body to assign `@n` in, which read as leaving it
  # nilable and refused the module outright.
  it "carries a type's class methods, and its bodyless initialize" do
    with_tempdir("iyimod_class_methods") do
      Dir.mkdir_p "std"
      File.write "std/counter.iyi", <<-IYI
        module std/counter

        pub struct Counter
          @n : Int32

          def initialize(@n : Int32)
          end

          def self.zero : Counter
            Counter.new(0)
          end

          def n : Int32
            @n
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/counter

        puts Std::Counter::Counter.zero.n
        puts Std::Counter::Counter.new(5).n
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "0\n5"

      declaration = Iyi::IyiMod.read(File.join("mods", "std", "counter.iyimod"))
        .exports.types.find! { |candidate| candidate.name == "Counter" }

      declaration.methods.find { |m| m.name == "zero" }.try(&.receiver).should eq "self"

      # `allocate` is put on every metaclass by the compiler and `new` is
      # synthesized from `initialize`; describing either as part of the
      # module's surface would be describing this compiler instead.
      declaration.methods.map(&.name).should eq ["initialize", "n", "zero"]

      File.delete "std/counter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "0\n5"
    end
  end

  # `MonoBodies`. A generic type's method exists once per instantiation, and
  # the instantiations belong to whoever writes them — so no machine code the
  # producer emits can serve a consumer, and the body is the only thing that
  # can travel. The consumer here instantiates at a type the producer never
  # did, which is the case that makes carrying the producer's object code no
  # answer at all. The fixture is `pack/box`, not `std/box`: that module
  # ships, and deleting the fixture would find the library's (the case the
  # "names a module whose path reaches another file now" example holds).
  it "ships a generic type's bodies, and the consumer specialises them" do
    with_tempdir("iyimod_mono_generic") do
      Dir.mkdir_p "pack"
      File.write "pack/box.iyi", <<-IYI
        module pack/box

        pub struct Box(T)
          @item : T

          def initialize(@item : T)
          end

          def item : T
            @item
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import pack/box

        puts Pack::Box::Box(Int32).new(7).item
        puts Pack::Box::Box(String).new("seven").item
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "7\nseven"

      artifact = Iyi::IyiMod.read(File.join("mods", "pack", "box.iyimod"))
      artifact.mono_bodies.keys.should contain "Box#item()"

      File.delete "pack/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "7\nseven"
    end
  end

  # The rest of what crosses the boundary once a consumer picks the arguments.
  #
  # The spec above and the one at the top of this file both write `Box(Int32)`,
  # which is the form that was never in doubt: an instance is a type the
  # consumer made and nothing marked it as the artifact's. These are the three
  # shapes where the generic itself is the owner, so each one asks the same
  # question the linker asked, on a different path. A method with its own
  # `forall`, whose specialisation is picked twice over; an `impl` written on
  # the generic, whose method is reached through the trait; and an instance of
  # an instance, which numbers a type nothing declared.
  it "specialises an imported generic however the consumer reaches it" do
    with_tempdir("iyimod_generic_reach") do
      Dir.mkdir_p "pack"
      File.write "pack/box.iyi", <<-IYI
        module pack/box

        pub trait Show
          abstract def show : String
        end

        pub struct Box(T)
          getter value : T

          def initialize(@value : T)
          end

          def map(& : T -> U) : Box(U) forall U
            Box(U).new(yield value)
          end
        end

        impl Show for Box(T) forall T
          def show : String
            "shown"
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import pack/box

        puts Pack::Box::Box.new(21).map { |v| v + v }.value
        puts Pack::Box::Box.new(1).show
        puts Pack::Box::Box.new(Pack::Box::Box.new(5)).value.value
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42\nshown\n5"

      File.delete "pack/box.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "42\nshown\n5"
    end
  end

  # The other half of `MonoBodies`, and the half no producer could ever emit
  # code for: a trait default is stencilled onto the implementing type, and the
  # implementing type here is declared by the *consumer*. There is no name the
  # producing build could have compiled it under.
  it "ships a trait's default bodies, and the consumer stencils them" do
    with_tempdir("iyimod_mono_trait") do
      Dir.mkdir_p "std"
      File.write "std/countable.iyi", <<-IYI
        module std/countable

        pub trait Countable
          abstract def count : Int32

          def doubled : Int32
            count + count
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/countable::{Countable}


        pub struct Three
        end

        impl Countable for Three
          def count : Int32
            3
          end
        end

        puts Three.new.doubled
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "6"

      artifact = Iyi::IyiMod.read(File.join("mods", "std", "countable.iyimod"))
      artifact.mono_bodies.keys.should contain "Countable#doubled()"

      File.delete "std/countable.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "6"
    end
  end

  # And the boundary, which is what keeps the two mechanisms from colliding. An
  # ordinary method of an ordinary type travels as machine code, so its body
  # must **not** also travel: a consumer given both would compile a definition
  # the artifact already carries, and the link would fail on a duplicate
  # symbol. Kept as an example because nothing else says it out loud.
  it "does not ship the body of a method that travels as machine code" do
    with_tempdir("iyimod_mono_boundary") do
      Dir.mkdir_p "app"
      File.write "app/greeter.iyi", <<-IYI
        module app/greeter

        pub struct Greeter
          def hello : String
            "hello"
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/greeter

        puts App::Greeter::Greeter.new.hello
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "greeter.iyimod"),
        want_object_code: true)
      artifact.mono_bodies.should be_empty
      artifact.object_code.map(&.name).should contain "App::Greeter::Greeter"

      File.delete "app/greeter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "hello"
    end
  end

  it "round-trips mono bodies" do
    with_temporary_file do |path|
      artifact = sample_artifact
      artifact.mono_bodies["Box#item()"] = "@item\n"
      Iyi::IyiMod.write artifact, path

      Iyi::IyiMod.read(path).mono_bodies.should eq({"Box#item()" => "@item\n"})
    end
  end

  it "renders a mono body under the declaration it belongs to" do
    declaration = type_declaration("Box", "generic struct",
      type_parameters: ["T"],
      methods: [signature("item", return_type: "T")])

    artifact = sample_artifact(types: [declaration])
    artifact.mono_bodies["Box#item()"] = "@item"

    io = IO::Memory.new
    Iyi::IyiMod.declarations artifact, io

    io.to_s.should contain "  def item : T\n    @item\n  end\n"
  end

  # III.5's initialiser is the one part of a module that is neither a
  # declaration nor the body of one, and it has to run — in DAG order, before
  # anything that imports the module. It travels as source text and is compiled
  # by the consumer, which is also what produces the module's constants and its
  # proc literals: nothing else could have.
  #
  # Two modules, because one would not show the ordering. `boot/config` is
  # imported by `boot/registry`, so it initialises first however the imports
  # are written — and `boot/registry`'s own `import` sits *below* a statement
  # of its own, which is the case III.5 rule 1 exists for.
  it "carries a module's initialiser, in import order" do
    with_tempdir("iyimod_initialiser") do
      Dir.mkdir_p "boot"
      File.write "boot/config.iyi", <<-IYI
        module boot/config

        puts "1. config"

        pub def name : String
          "iyi"
        end
        IYI
      File.write "boot/registry.iyi", <<-IYI
        module boot/registry

        puts "2. registry, above its own import"

        import boot/config

        puts "3. registry, below it"

        pub def greeting : String
          Boot::Config.name
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/registry

        puts "4. main"
        puts Boot::Registry.greeting
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "1. config\n2. registry, above its own import\n3. registry, below it\n4. main\niyi"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "registry.iyimod"))
      artifact.has_initialiser.should be_false
      artifact.initialiser.lines.size.should eq 2

      File.delete "boot/config.iyi"
      File.delete "boot/registry.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # What the initialiser does *not* reach: a statement in a type body. It is
  # not a declaration, so nothing in `Exports` carries it, and it is not the
  # module's own top level, so the initialiser does not either. Refused rather
  # than linked, because the alternative is a program that runs with that part
  # silently missing.
  #
  # A class variable was what this was written with, and that was wrong: its
  # value travels in `TypeDecl#class_vars` and the consumer initialises it —
  # `it "carries a class variable's value"` below is the proof. A bare `puts`
  # is the shape that has nowhere to go.
  it "refuses to generate code against a module whose type body has to run" do
    with_tempdir("iyimod_type_body") do
      Dir.mkdir_p "boot"
      File.write "boot/counter.iyi", <<-IYI
        module boot/counter

        pub struct Counter
          puts "the type body ran"

          def count : Int32
            7
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/counter

        puts Boot::Counter::Counter.new.count
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, File.expand_path("unused")

      Iyi::IyiMod.read(File.join("mods", "boot", "counter.iyimod"))
        .has_initialiser.should be_true

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      expect_raises(Iyi::TypeException, /has code inside a type body/) do
        consumer.compile source, File.expand_path("from-artifact")
      end

      # Front end only, which is what the artifact does carry: still fine.
      checker = create_spec_compiler
      checker.prelude = "iyi/prelude"
      checker.use_iyimod = "mods"
      checker.no_codegen = true
      checker.compile source, File.expand_path("unused-too")
    end
  end

  # And what it does reach, which is the other half of the same rule. A
  # constant in a type body is not runnable code the artifact drops: it is a
  # declaration with a value, and it travels qualified — `Point::MAX = 10` —
  # the way `iyi tool bind` has always carried a bound Crystal namespace's.
  #
  # Without that it was in the artifact nowhere at all: not in `Exports`,
  # which carries types and signatures, and not in the initialiser, which
  # stopped at the type's body. So the module read as one whose type body has
  # to run and every consumer of it was refused — thirteen of `src/std`'s own
  # modules, `std/math` over `PI`.
  #
  # The sources are deleted before the consuming build, so nothing here can
  # pass by reading them, and the program is *run*: a constant that arrives
  # declared and never initialised answers zero, which a compile would not
  # catch.
  #
  # All three spellings, because they reach the consumer by different paths:
  # `pub` is read by the consumer's own source, the private one only by a body
  # this module compiled into the artifact's object code, and the nested one
  # has a name that is two namespaces deep.
  it "carries the constants a type body declares" do
    with_tempdir("iyimod_type_constants") do
      Dir.mkdir_p "boot"
      File.write "boot/limits.iyi", <<-IYI
        module boot/limits

        pub struct Limits
          pub MAX = 10
          private SCALE = 3

          pub struct Inner
            pub DEPTH = 2
          end

          pub def self.scaled : Int32
            MAX * SCALE
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/limits

        puts Boot::Limits::Limits::MAX
        puts Boot::Limits::Limits.scaled
        puts Boot::Limits::Limits::Inner::DEPTH
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "10\n30\n2"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "limits.iyimod"))
      artifact.has_initialiser.should be_false
      artifact.initialiser.lines.should eq [
        "pub Limits::MAX = 10",
        "Limits::SCALE = 3",
        "pub Limits::Inner::DEPTH = 2",
      ]

      File.delete "boot/limits.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # Two more things the check read as code, both of them declarations.
  #
  # A `lib` body is the first: a `fun` is a C prototype, a `type` names a
  # pointer, a `struct` is a layout. Nothing in one runs, so nothing in one
  # can be the piece of setup III.5 is about — and every module with a `lib`
  # in it was refused. `std/math` binds two LLVM intrinsics and its consumers
  # were told it "has code inside a type body that has to run".
  #
  # A macro is the second, and it is where the constants of the modules that
  # bind a platform live: `std/file` writes `AT_FDCWD` inside a `{% if
  # flag?(:linux) %}`. A `{% for %}` here rather than a `flag?`, so the
  # expansion is the same on every machine this spec runs on; the node is the
  # same `ExpandableNode` either way.
  #
  # Run, with the source deleted, because the point is not that the build is
  # allowed: it is that `LOW` is 1 on the far side and the `fun` still reaches
  # the intrinsic.
  #
  # And a macro in the `lib` is more of the `lib`: `std/math` writes its
  # `llvm.fma` binding inside `{% if flag?(:aarch64) %}`, and on arm64 alone
  # the `fun`s that expanded read as code and refused the module.
  it "carries a lib's declarations and the constants a macro writes" do
    with_tempdir("iyimod_lib_and_macro") do
      Dir.mkdir_p "boot"
      File.write "boot/plat.iyi", <<-IYI
        @[Unsafe("declares the platform's C library")]
        module boot/plat

        lib LibPlat
          type Handle = Void*

          struct Pair
            a : Int32
            b : Int32
          end

          fun plat_abs = "llvm.fabs.f64"(x : Float64) : Float64
          {% for name in ["plat_sqrt"] %}
            fun {{name.id}} = "llvm.sqrt.f64"(x : Float64) : Float64
          {% end %}
        end

        pub struct Plat
          {% for name, value in {"LOW" => 1, "HIGH" => 2} %}
            pub {{name.id}} = {{value}}
          {% end %}

          pub def self.magnitude(x : Float64) : Float64
            LibPlat.plat_abs(x)
          end

          pub def self.root(x : Float64) : Float64
            LibPlat.plat_sqrt(x)
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/plat

        puts Boot::Plat::Plat::LOW
        puts Boot::Plat::Plat::HIGH
        puts Boot::Plat::Plat.magnitude(-2.5)
        puts Boot::Plat::Plat.root(6.25)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "1\n2\n2.5\n2.5"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "plat.iyimod"))
      artifact.has_initialiser.should be_false
      artifact.initialiser.lines.should eq ["pub Plat::LOW = 1", "pub Plat::HIGH = 2"]

      File.delete "boot/plat.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # A `--release` build that writes artifacts writes their object code.
  # It forced one LLVM module, so no type had a unit of its own: the
  # artifact said "object code (none)", and a `--release` consumer of it
  # internalised the declarations it read and the IR was refused -
  # "Global is external, but doesn't have external or weak linkage!".
  #
  # And a `--release` consumer made private what that object code reaches
  # by name in the program that links it. `x // 2` reaches nothing, so this
  # passed while a module with a checked `+` did not link
  # (`__iyi_raise_overflow`), nor one with a class (`:type_id`, `:headed`);
  # on Windows a `defer` names the `void*` type descriptor, which a consumer
  # with no `defer` of its own never defined. A struct changed through a
  # getter is the last line: called rather than inlined, the getter answered
  # a copy and the bump was lost, in the build writing the artifact too.
  it "carries object code from a release build to a release consumer" do
    with_tempdir("iyimod_release_object_code") do
      Dir.mkdir_p "boot"
      File.write "boot/half.iyi", <<-IYI
        module boot/half

        pub struct Half
          pub def self.of(x : Int32) : Int32
            x // 2
          end
        end

        pub struct Counter
          property n : Int32

          def initialize(@n : Int32)
          end

          def bump : Nil
            @n += 1
          end
        end

        pub class Holder
          property counter : Counter

          def initialize(@counter : Counter)
          end
        end

        pub def add1(x : Int32) : Int32
          x + 1
        end

        pub def with_defer(log : Array(String)) : Int32
          defer log << "defer"
          log << "body"
          7
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/half

        puts Boot::Half::Half.of(84)
        puts Boot::Half.add1(41)
        h = Boot::Half::Holder.new(Boot::Half::Counter.new(1))
        h.counter.bump
        puts h.counter.n
        log = [] of String
        puts Boot::Half.with_defer(log)
        puts log.join(",")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "42\n42\n2\n7\nbody,defer"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.release!
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "half.iyimod"), want_object_code: true)
      artifact.object_code.empty?.should be_false

      File.delete "boot/half.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.release!
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  {% if flag?(:darwin) %}
    it "carries per-type release diagnostic objects to a source-absent consumer" do
      with_tempdir("iyimod_release_diagnostic_objects") do
        with_env("IYI_RELEASE_PARTITIONS": "4") do
          Dir.mkdir_p "boot"
          Dir.mkdir_p "source"
          Dir.mkdir_p "consumer"
          Dir.mkdir_p "rewritten"
          File.write "boot/half.iyi", <<-IYI
            module boot/half

            pub class Values
              pub OFFSET = 1
            end

            @[NoInline]
            pub def make(offset : Int32) : Proc(Int32, Int32)
              ->(n : Int32) do
                raise "artifact closure trace" if n < 0
                n + offset + Values::OFFSET
              end
            end
            IYI
          File.write "main.iyi", <<-IYI
            module main
            import boot/half

            @[NoInline]
            def invoke(action : Proc(Int32, Int32), n : Int32) : Int32
              action.call(n)
            end

            target = Boot::Half.make(0)
            f = ->(n : Int32) { target.call(n) * 2 }
            input = Program.env("IYI_DIAGNOSTIC_TRACE") == "1" ? -1 : 20
            puts invoke(f, input)
            IYI
          source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
          producer = create_spec_compiler
          producer.prelude = "iyi/prelude"
          producer.release!
          producer.emit_iyimod = "mods"
          producer.emit_frame_provenance = "producer-frames.json"
          producer.compile source, File.expand_path("source/program")
          `./source/program`.chomp.should eq("42")
          artifact = Iyi::IyiMod.read(File.join("mods", "boot", "half.iyimod"), want_object_code: true)
          artifact.object_code.should_not be_empty
          artifact.object_code.map(&.name).should contain("Boot::Half")
          section = artifact.diagnostic_provenance.not_nil!
          section.validate_objects!(artifact.object_code)
          section.objects.each_value { |object| object.partition.should be_nil }
          section.objects.values.any? { |object| !object.definitions.empty? }.should be_true
          section.objects.values.any? { |object| object.unit_name == "Boot::Half" && !object.definitions.empty? }.should be_true
          Dir.mkdir_p "rewritten/boot"
          rewritten_path = File.join("rewritten", "boot", "half.iyimod")
          Iyi::IyiMod.write artifact, rewritten_path
          rewritten = Iyi::IyiMod.read(rewritten_path, want_object_code: true)
          rewritten.object_code.should eq(artifact.object_code)
          rewritten_section = rewritten.diagnostic_provenance.not_nil!
          rewritten_section.validate_objects!(rewritten.object_code)
          rewritten_section.objects.should eq(section.objects)
          rewritten_section.fragments.should eq(section.fragments)
          rewritten_section.regexes.should eq(section.regexes)

          File.delete "boot/half.iyi"
          consumer = create_spec_compiler
          consumer.prelude = "iyi/prelude"
          consumer.release!
          consumer.use_iyimod = "mods"
          consumer.emit_frame_provenance = "consumer-frames.json"
          consumer.compile source, File.expand_path("consumer/program")
          `./consumer/program`.chomp.should eq("42")
          manifest = JSON.parse(File.read("consumer-frames.json"))
          manifest["schema"].as_i.should eq(5)
          inputs = manifest["object_inputs"].as_a
          bound_ids = manifest["bindings"].as_a.map { |binding| binding["link_input_id"].as_i }.to_set
          bound = inputs.select { |input| bound_ids.includes?(input["link_input_id"].as_i) }
          bound.any? { |input| input["producer"]["kind"].as_s == "artifact_object" }.should be_true
          bound.any? { |input| input["producer"]["kind"].as_s == "current_unit" }.should be_true
          File.delete File.join("mods", "boot", "half.iyimod")
          File.exists?("boot/half.iyi").should be_false
          File.exists?(File.join("mods", "boot", "half.iyimod")).should be_false
          rewritten_consumer = create_spec_compiler
          rewritten_consumer.prelude = "iyi/prelude"
          rewritten_consumer.release!
          rewritten_consumer.use_iyimod = "rewritten"
          rewritten_consumer.emit_frame_provenance = "rewritten-frames.json"
          rewritten_consumer.compile source, File.expand_path("rewritten/program")
          `./rewritten/program`.chomp.should eq("42")
          rewritten_manifest = JSON.parse(File.read("rewritten-frames.json"))
          rewritten_manifest["schema"].as_i.should eq(5)
          rewritten_inputs = rewritten_manifest["object_inputs"].as_a
          rewritten_ids = rewritten_manifest["bindings"].as_a.map { |binding| binding["link_input_id"].as_i }.to_set
          rewritten_bound = rewritten_inputs.select { |input| rewritten_ids.includes?(input["link_input_id"].as_i) }
          rewritten_bound.any? { |input| input["producer"]["kind"].as_s == "artifact_object" }.should be_true
          rewritten_bound.any? { |input| input["producer"]["kind"].as_s == "current_unit" }.should be_true

          # Exercise both retained closure bodies in a real backtrace. Normal
          # runs above still prove the value independently of the failure path.
          [
            {"source/program", "producer-frames.json", "source-trace.log"},
            {"consumer/program", "consumer-frames.json", "consumer-trace.log"},
            {"rewritten/program", "rewritten-frames.json", "rewritten-trace.log"},
          ].each do |program, manifest_path, trace_path|
            trace = IO::Memory.new
            result = Process.run(File.expand_path(program), env: {"IYI_DIAGNOSTIC_TRACE" => "1"},
              output: trace, error: trace)
            result.success?.should be_false
            trace.to_s.should contain("artifact closure trace")
            File.write(trace_path, trace.to_s)
            observed = trace.to_s.lines.compact_map do |line|
              if match = line.match(/^\d+ +\S+ +0x[0-9a-fA-F]{16} (.*) \+ \d+/)
                match[1]
              end
            end.to_set
            evidence = JSON.parse(File.read(manifest_path))
            entries = evidence["object_inputs"].as_a
            observed_kinds = evidence["bindings"].as_a.compact_map do |binding|
              name = binding["definition"]["native_object_symbol"].as_s
              name.starts_with?("_").should be_true
              if observed.includes?(name.byte_slice(1, name.bytesize - 1))
                entries[binding["link_input_id"].as_i]["producer"]["kind"].as_s
              end
            end.to_set
            if program != "source/program"
              observed_kinds.includes?("artifact_object").should be_true
              observed_kinds.includes?("current_unit").should be_true
            end
          end

          comparator = File.expand_path("../../bench/frames_equivalent.py", __DIR__)
          [
            {"consumer/program", "consumer-frames.json", "consumer-trace.log"},
            {"rewritten/program", "rewritten-frames.json", "rewritten-trace.log"},
          ].each do |program, manifest_path, trace_path|
            result = Process.run("python3", [
              comparator, "--strict-provenance", "--require-frames",
              "--source-manifest", "producer-frames.json", "--artifact-manifest", manifest_path,
              "--source-executable", "source/program", "--artifact-executable", program,
              "source-trace.log", trace_path,
            ], output: Process::Redirect::Inherit, error: Process::Redirect::Inherit)
            result.success?.should be_true
          end
        end
      end
    end
  {% end %}

  # The same reach without `--release`, where each type is a unit of its own
  # and only two things were missing. A getter's caller has only a header,
  # and a call answers a copy where the inlined body answered the field
  # itself: `h.counter.bump` left 1 in the build writing the artifact and in
  # the one reading it. And on Windows a module's `defer` is a catch pad over
  # `void*`, whose type descriptor the main module defines when its own code
  # first asks - which a consumer with no `defer`, `rescue` or `raise` of its
  # own never did: `unresolved external symbol ... (??_R0PEAX@8)`.
  it "changes a struct through an artifact's getter, and links its defer" do
    with_tempdir("iyimod_getter_and_defer") do
      Dir.mkdir_p "boot"
      File.write "boot/shelf.iyi", <<-IYI
        module boot/shelf

        pub struct Counter
          property n : Int32

          def initialize(@n : Int32)
          end

          def me : self
            self
          end

          def bump : Nil
            @n += 1
          end
        end

        pub class Holder
          property counter : Counter

          def initialize(@counter : Counter)
          end
        end

        pub def with_defer(log : Array(String)) : Int32
          defer log << "defer"
          log << "body"
          7
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/shelf

        h = Boot::Shelf::Holder.new(Boot::Shelf::Counter.new(1))
        h.counter.bump
        puts h.counter.n
        c = Boot::Shelf::Counter.new(1)
        c.me.bump
        puts c.n
        log = [] of String
        puts Boot::Shelf.with_defer(log)
        puts log.join(",")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "2\n2\n7\nbody,defer"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      File.delete "boot/shelf.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # A class variable's value travels, so a module with one is consumable.
  #
  # This was the case the type-body rule was written for, on the reading that
  # a class variable's initialiser belongs to the type and nothing carries it.
  # Half of that is true — it is not in the module's initialiser — and the
  # other half stopped being true when `TypeDecl#class_vars` started carrying
  # the value as written, so the consumer declares `@@names : Array(String) =
  # ["a", "b"]` and initialises it like any other.
  #
  # Three shapes, because "the value travels" has to mean more than a number:
  # a literal, a collection literal (whose node `CleanupTransformer` rewrites
  # into temporaries, which is why the *source* is what travels), and one
  # whose value calls a private def of the module — a body the consumer never
  # sees, reached in the artifact's own object code.
  it "carries a class variable's value" do
    with_tempdir("iyimod_class_var_value") do
      Dir.mkdir_p "boot"
      File.write "boot/reg.iyi", <<-IYI
        module boot/reg

        private def seed : Int32
          41
        end

        pub struct Reg
          @@count = 7
          @@names = ["a", "b"]
          @@base : Int32 = seed + 1

          pub def self.report : String
            @@count.to_s + ":" + @@names.join(",") + ":" + @@base.to_s
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/reg

        puts Boot::Reg::Reg.report
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "7:a,b:42"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      Iyi::IyiMod.read(File.join("mods", "boot", "reg.iyimod"))
        .has_initialiser.should be_false

      File.delete "boot/reg.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # An enum the module keeps to itself travels as its members, which is what
  # an enum is.
  #
  # The exported side has always written them down. The carried side — a type
  # a consumer cannot name but the module's own object code does — fell
  # through to the branch built for a class, and wrote the *question methods*
  # the consumer's own compiler generates from the members while writing no
  # members at all. The consumer read `private enum Kind` with a `Large?` in
  # it and nothing to number, and said `enum Kind must have at least one
  # member` about a type nobody outside the module can write.
  #
  # The numbers are asserted, not just the names: the module's object code was
  # compiled against these, and a consumer that renumbered from zero would
  # agree with it only by luck. `@[Flags]` is here for the pair the compiler
  # adds wherever a flags enum is declared — writing `None` and `All` down
  # hands the consumer its own two back.
  it "carries the members of an enum it does not export" do
    with_tempdir("iyimod_carried_enum") do
      Dir.mkdir_p "boot"
      File.write "boot/kinds.iyi", <<-IYI
        module boot/kinds

        enum Kind
          Small  = 3
          Large  = 9
        end

        @[Flags]
        enum Mode
          Read
          Write
          Append
        end

        pub struct Holder
          pub def self.describe : String
            Kind::Large.to_s + ":" + Kind::Large.value.to_s + ":" + (Mode::Read | Mode::Write).to_s
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/kinds

        puts Boot::Kinds::Holder.describe
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "Large:9:Read | Write"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      declarations = String.build do |io|
        Iyi::IyiMod.declarations(Iyi::IyiMod.read(File.join("mods", "boot", "kinds.iyimod")), io)
      end
      declarations.should contain "private enum Kind : Int32\n  Small = 3\n  Large = 9\nend"
      declarations.should contain "@[Flags]\nprivate enum Mode : Int32\n  Read = 1\n  Write = 2\n  Append = 4\nend"

      File.delete "boot/kinds.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # And the methods the author wrote on an enum, which are not the ones the
  # compiler writes.
  #
  # An enum gets a question method per member wherever it is declared, so
  # carrying those hands the consumer a second copy of what its own compiler
  # already made — which is why an enum travelled with no methods at all. A
  # `def self.native` is neither: nobody but the module wrote it, and a
  # consumer without it said `undefined method 'native' for
  # Std::Path::Path::Kind.class`. `std/path` and `std/dir` stopped there.
  #
  # Both sides, because a `def self.` lives on the metaclass and that is most
  # of what an enum's author writes. Run, because the point is the call: a
  # declaration that arrived without machine code behind it would link
  # against nothing.
  it "carries the methods an enum's author wrote, and not the compiler's" do
    with_tempdir("iyimod_enum_methods") do
      Dir.mkdir_p "boot"
      File.write "boot/kind.iyi", <<-IYI
        module boot/kind

        pub enum Kind : UInt8
          POSIX   = 0
          WINDOWS = 1

          def self.native : Kind
            Kind::POSIX
          end

          def label : String
            posix? ? "posix" : "windows"
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/kind

        puts Boot::Kind::Kind.native.label
        puts Boot::Kind::Kind::WINDOWS.label
        puts Boot::Kind::Kind::WINDOWS.windows?
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "posix\nwindows\ntrue"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      kind = Iyi::IyiMod.read(File.join("mods", "boot", "kind.iyimod"))
        .exports.types.find! { |declaration| declaration.name == "Kind" }
      kind.methods.map(&.name).should eq ["label", "native"]

      File.delete "boot/kind.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # A header with a splat in it: keyword-only parameters, called by name.
  #
  # This crashed the compiler rather than refusing anything. A def read from
  # an artifact is a header, and headers take the forwarding path through
  # `expand_default_arguments` — evaluate the defaults here, call the symbol
  # there — which is written for a plain parameter list and passes the whole
  # of it by position. A bare `*` is a nameless `Arg` in that list: the build
  # died on `Nil assertion failed` reading its missing default, or on `Index
  # out of bounds` where the call named fewer parameters than the def has.
  #
  # A def with a splat keeps its body instead, which is what upstream does
  # with one and what links: the producer emits a symbol per named-argument
  # combination — `Span::new:days<Int64>` — and the expansion built here
  # carries the same name, built from the same named arguments. The body it
  # keeps is the header's `Nop`, so the expansion has to be marked a header
  # too, or codegen inlines the nothing it sees and the call vanishes.
  #
  # `self.new` because that is the shape the library writes — `Time::Span`
  # has one, and `std/time`, `std/json` and `std/kernel` were all refused
  # over it — and one more named `make`, because `new` has an expansion path
  # of its own and the defect is in the other one.
  it "carries a header whose parameters are keyword-only" do
    with_tempdir("iyimod_splat_header") do
      Dir.mkdir_p "boot"
      File.write "boot/span.iyi", <<-IYI
        module boot/span

        pub struct Span
          @ticks : Int64

          def initialize(@ticks : Int64)
          end

          pub def self.new(*, days : Int64 = 0_i64, hours : Int64 = 0_i64) : Span
            Span.new(days * 24_i64 + hours)
          end

          pub def self.make(*, hours : Int64) : Span
            Span.new(hours)
          end

          pub def ticks : Int64
            @ticks
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/span

        puts Boot::Span::Span.new(days: 2_i64).ticks
        puts Boot::Span::Span.new(hours: 5_i64).ticks
        puts Boot::Span::Span.new(days: 1_i64, hours: 3_i64).ticks
        puts Boot::Span::Span.make(hours: 9_i64).ticks
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "48\n5\n27\n9"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      File.delete "boot/span.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # An alias travels as the type expression the module wrote.
  #
  # It used to travel as what the name resolved to, and a resolved type is
  # not always something that can be written down again. Two shapes here,
  # both taken from `src/std`:
  #
  # * `pub alias Ary = ::Array` is an uninstantiated generic, and one prints
  #   with its type variables — the consumer read `alias Ary = Array(T)` and
  #   said `undefined constant T` about a letter nobody wrote.
  # * `pub alias Array = ::Array` hands a prelude type out under its own
  #   name, and a resolved name has no `::` on it: inside `module Boot::Ring`
  #   the consumer read `alias Array = Array`, which is the alias itself —
  #   `infinite recursive definition of alias`. `std/annotations`,
  #   `std/bit_array` and `std/static_array` each do exactly this.
  #
  # The written form resolves on the far side because the declarations text
  # replays the module's imports with their names, its requires, and
  # declares its own nested types, which is the whole of what the module
  # itself could name.
  it "carries an alias as the module wrote it" do
    with_tempdir("iyimod_alias_value") do
      Dir.mkdir_p "boot"
      File.write "boot/ring.iyi", <<-IYI
        module boot/ring

        pub alias Array = ::Array
        pub alias Ary = ::Array

        pub def first(items : Array(Int32)) : Int32
          items[0]
        end

        pub def last(items : Ary(Int32)) : Int32
          items[items.size - 1]
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/ring

        puts Boot::Ring.first([7, 8])
        puts Boot::Ring.last([7, 8])
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "7\n8"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      declarations = String.build do |io|
        Iyi::IyiMod.declarations(Iyi::IyiMod.read(File.join("mods", "boot", "ring.iyimod")), io)
      end
      declarations.should contain "pub alias Array = ::Array"
      declarations.should contain "pub alias Ary = ::Array"

      File.delete "boot/ring.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # A parameter written wider than the argument this build passed.
  #
  # The consumer keys a call on what the declaration says — that is the
  # contract, and `Call#iyi_artifact_arg_types` widens every argument to it —
  # so the object code has to have been keyed the same way. Inside an
  # ordinary build it is not: codegen is demand-driven, `note = "hi"`
  # compiles `note=<String>`, and the consumer asks the linker for
  # `note=<(String | Nil)>`. It linked no further, with the artifact's own
  # object file naming the line.
  #
  # `iyi bind` answers this with a keep file, a second build that names every
  # declared signature. An `--emit-iyimod` build has no second build, so the
  # body travels instead and the consumer compiles it at the types it asked
  # for.
  #
  # Three shapes, because "wider" has three spellings: a union, a nilable
  # (which is one), and an abstract number, where the declared type is `Int`
  # and a value of it is held as `Int+`.
  #
  # Run with the source deleted, because a link is the whole of what fails
  # here — the front end was always happy.
  it "carries the body of a method whose parameter is wider than its callers" do
    with_tempdir("iyimod_widened_parameters") do
      Dir.mkdir_p "boot"
      File.write "boot/crate.iyi", <<-IYI
        module boot/crate

        pub class Crate
          @note : String?

          def initialize
            @note = nil
          end

          pub def note=(value : String?) : Nil
            @note = value
          end

          pub def note : String
            @note || "none"
          end

          pub def tag(kind : Int32 | Symbol) : String
            kind.to_s
          end
        end

        pub def sized(n : Int) : Int64
          n.to_i64 * 2_i64
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/crate

        crate = Boot::Crate::Crate.new
        crate.note = "hi"
        puts crate.note
        puts crate.tag(7)
        puts Boot::Crate.sized(21)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "hi\n7\n42"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      # The bodies are in the artifact, which is what makes the link work.
      keys = Iyi::IyiMod.read(File.join("mods", "boot", "crate.iyimod")).mono_bodies.keys
      keys.should contain "Crate#note=(value : String | ::Nil)"
      keys.should contain "Crate#tag(kind : Int32 | Symbol)"
      keys.should contain "boot/crate#sized(n : Int)"
      # And the one whose parameters cannot disagree is not among them.
      keys.should_not contain "Crate#note()"

      File.delete "boot/crate.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected
    end
  end

  # `@[Primitive]` is a declaration a module makes, so it travels.
  #
  # A def wearing it has no body — the instruction is the body, and the
  # compiler puts one there — so the rule that keeps `allocate` and the
  # prelude's own instructions out of an artifact ("anything whose body is a
  # `Primitive` is the compiler's") swept it up too. `std/float` declares the
  # whole matrix for `Float32` the way the prelude declares it for `Float64`,
  # and a consumer that read the artifact got a `Float32` with no arithmetic:
  # `wrong number of arguments for 'Float32#+' (given 1, expected 0)`, about
  # the prelude's unary plus, which was the only `+` left.
  #
  # The annotation is what makes the consumer's copy the same instruction, so
  # it travels on the signature — the format change this needed. No body
  # travels with it: there is none, and one would be a promise of a symbol
  # nobody emitted.
  #
  # On a reopened prelude type, which is where a module writes these, and run
  # with the source deleted so the arithmetic is the artifact's.
  it "carries a @[Primitive] the module declared" do
    with_tempdir("iyimod_primitive") do
      Dir.mkdir_p "boot"
      File.write "boot/f32.iyi", <<-IYI
        @[Unsafe("declares a float operator as a compiler primitive")]
        module boot/f32

        struct ::Float32
          @[::Primitive(:binary)]
          def +(other : Float32) : Float32
          end

          @[::Primitive(:convert)]
          def to_i32 : Int32
          end

          def doubled : Float32
            self + self
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/f32

        puts (1.5_f32 + 2.0_f32).to_i32
        puts 1.5_f32.doubled.to_i32
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      expected = "3\n3"

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq expected

      File.delete "boot/f32.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq expected

      # And what carried it: the annotation on the signature, and no body,
      # because an instruction has none.
      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "f32.iyimod"))
      float = artifact.reopened.find! { |declaration| declaration.name == "::Float32" }
      plus = float.methods.find! { |signature| signature.name == "+" }
      plus.annotations.should eq ["@[::Primitive(:binary)]"]
      artifact.mono_bodies.keys.should_not contain "::Float32#+(other : Float32)"
      artifact.mono_bodies.keys.should contain "::Float32#doubled()"
    end
  end

  # A `module` the module keeps to itself, which its own travelling bodies
  # name.
  #
  # The carried side of `Exports` took classes, structs and enums; a nested
  # module fell through it, and its object code travelled all the same — one
  # unit per non-generic type declared under the module. So the artifact
  # carried the machine code of a type it never declared, and the first body
  # that named it stopped the consumer: `undefined constant
  # Std::Float::Float32Text`, about `module Float32Text`, which is how
  # `std/float` writes the single's printer and what `::Float32#to_s` calls.
  # `std/float`, `std/math` and `std/benchmark` were all unusable as
  # artifacts.
  #
  # Its methods come from both sides, because a module keeps everything on
  # the metaclass: `def self.twice` is not on the module's own `defs`, and
  # walking that side alone carried a `module Helper` with nothing in it.
  #
  # Named through a reopened prelude type, which is the shape that makes the
  # body travel — a reopened type's methods are the consumer's to compile —
  # and run with the source deleted.
  it "carries a module it keeps to itself" do
    with_tempdir("iyimod_nested_module") do
      Dir.mkdir_p "boot"
      File.write "boot/num.iyi", <<-IYI
        module boot/num

        module Helper
          def self.twice(n : Int32) : Int32
            n * 2
          end
        end

        struct ::Int32
          def quadrupled : Int32
            Boot::Num::Helper.twice(Boot::Num::Helper.twice(self))
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/num

        puts 3.quadrupled
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "12"

      declarations = String.build do |io|
        Iyi::IyiMod.declarations(Iyi::IyiMod.read(File.join("mods", "boot", "num.iyimod")), io)
      end
      declarations.should contain "module Helper\n  def self.twice(n : Int32) : Int32"

      File.delete "boot/num.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "12"
    end
  end

  # The other side of the one above: a module under this one's path is not
  # a module this one keeps.
  #
  # `pkg/child` is the namespace `Pkg::Child`, inside `pkg`'s `Pkg`, and the
  # walks that gather `pkg`'s artifact went into every module they found
  # there. `pkg.iyimod` carried the child's declarations, aliases and
  # machine code a second time, so a program built from both artifacts was
  # refused (`alias Num is already defined`) or failed to link (LNK2005).
  # A module with a `module` header of its own has its own artifact; the
  # walks stop at it.
  it "leaves a module under its path to that module's own artifact" do
    with_tempdir("iyimod_nested_unit") do
      modules = {
        "pkg/child.iyi" => <<-IYI,
          module pkg/child

          pub alias Num = Int32 | Int64

          pub class Foo
            def initialize(@x : Int32)
            end

            def x : Int32
              @x
            end
          end

          pub def make : Foo
            Foo.new(3)
          end
          IYI
        "pkg.iyi" => <<-IYI,
          module pkg

          import pkg/child::*

          pub def run : Int32
            n : Num = make.x
            n.to_i32 * 2
          end
          IYI
      }
      main = <<-IYI
        module main

        import pkg
        import pkg/child::*

        puts Pkg.run
        puts make.x
        IYI

      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "6\n3\n"
      from_artifact.should eq from_source

      parent = Iyi::IyiMod.read(File.join("mods", "pkg.iyimod"))
      child = Iyi::IyiMod.read(File.join("mods", "pkg", "child.iyimod"))

      parent.object_code.map(&.name).select(&.starts_with?("Pkg::Child")).should be_empty
      parent.layouts.map(&.[0]).select(&.starts_with?("Pkg::Child")).should be_empty
      (parent.object_code.map(&.name) & child.object_code.map(&.name)).should be_empty

      declarations = String.build do |io|
        Iyi::IyiMod.declarations(parent, io)
      end
      declarations.should_not contain "class Foo"
      declarations.should_not contain "def make"
      declarations.should_not contain "alias Num"
    end
  end

  # A generic's splat parameter is part of its declaration.
  #
  # `*T` and `T` are different things and the parser says so: `struct
  # ::Tuple(T)` is `type var must be *T, not T`. The artifact carried the
  # names and not the marker, so the two types the prelude declares that way
  # — `Tuple` and `NamedTuple`, both reopened by `src/std` — could not be
  # read back at all, and `std/tuple` and `std/named_tuple` were refused
  # before anything in them was looked at.
  #
  # The marker travels in the list, which is the convention a def's splat
  # already uses in `Signature#parameters`: the renderer joins these
  # verbatim, so the marker is the text.
  it "carries a generic's splat parameter" do
    with_tempdir("iyimod_splat_parameter") do
      Dir.mkdir_p "boot"
      File.write "boot/pack.iyi", <<-IYI
        module boot/pack

        pub struct Bag(*T)
          pub def self.count : Int32
            {{ T.size }}
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/pack

        puts Boot::Pack::Bag(Int32, String, Bool).count
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "3"

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "pack.iyimod"))
      bag = artifact.exports.types.find! { |declaration| declaration.name == "Bag" }
      bag.type_parameters.should eq ["*T"]

      File.delete "boot/pack.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "3"
    end
  end

  # A class hierarchy crosses the boundary: the `<` edge, the `abstract`
  # word, and the field types the hierarchy makes virtual.
  #
  # Three things the artifact dropped, and each of them alone is enough to
  # stop a consumer:
  #
  # * The edge. A subclass's `fields` are its *own* — the inherited ones come
  #   with the superclass — so `pub class Memory < IyiIO` came back as `pub
  #   class Memory` and the consumer said `undefined method 'puts' for
  #   Std::Io::Memory`. Worse than the method: a type id is assigned by
  #   walking that tree, so a consumer with a missing edge numbers it
  #   differently and a match against a virtual type answers wrongly and
  #   links cleanly.
  # * The word. An `abstract def` is only allowed on an abstract type, so a
  #   class that lost `abstract` carried a requirement it could not hold:
  #   `can't define abstract def on non-abstract class`, which is where
  #   `std/log` stopped.
  # * The field's type. `Sink+` is how a virtual type prints and not a name
  #   anybody can write: the parser read `Sink`, then `+` as an operator, and
  #   the line after it as its operand — `can't declare def dynamically`,
  #   pointing at a def that was fine. `std/io` and `std/symbol` stopped
  #   there.
  #
  # The superclass is written relative to the namespace it is declared in,
  # which is what lets `inheritance_order` place it: that walk matches names
  # against *siblings*, and a full path matched none of them, so a subclass
  # was rendered above the class it names.
  #
  # Run with the source deleted, and through the base: the answer needs the
  # inherited field, the inherited method and the subclass's own.
  it "carries a class hierarchy" do
    with_tempdir("iyimod_hierarchy") do
      Dir.mkdir_p "boot"
      File.write "boot/sink.iyi", <<-IYI
        module boot/sink

        pub abstract class Sink
          @tag : String

          def initialize(@tag : String)
          end

          pub def label : String
            @tag
          end

          pub abstract def take(n : Int32) : Int32
        end

        pub class Doubler < Sink
          pub def take(n : Int32) : Int32
            n * 2
          end
        end

        pub class Holder
          @sink : Sink

          def initialize(@sink : Sink)
          end

          pub def run(n : Int32) : String
            @sink.label + ":" + @sink.take(n).to_s
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/sink

        puts Boot::Sink::Holder.new(Boot::Sink::Doubler.new("d")).run(21)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "d:42"

      declarations = String.build do |io|
        Iyi::IyiMod.declarations(Iyi::IyiMod.read(File.join("mods", "boot", "sink.iyimod")), io)
      end
      declarations.should contain "pub abstract class Sink"
      declarations.should contain "pub class Doubler < Sink"
      # The field, named and not printed: no `+`, and global, because it is
      # read inside the module.
      declarations.should contain "@sink : ::Boot::Sink::Sink\n"

      File.delete "boot/sink.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "d:42"
    end
  end

  # A signature the consumer keys a symbol on differently from the build
  # that compiled it, in all three places a symbol carries one.
  #
  # A consumer types a call from the declaration, so what it asks the linker
  # for is what the declaration says; the producer's codegen is
  # demand-driven, so what it wrote is what its own program happened to
  # need. Where the two can differ the body travels instead, the way a
  # block-taking def's already does. Three ways they differ, and this
  # program hits all three at once:
  #
  # * the **return** — `def self.square(side : Int32) : Shape` was asked for
  #   as `square<Int32>:Shape+`, where the producer, whose body returns
  #   exactly a `Square`, wrote the answer it had;
  # * the **receiver** — `shape.twice` on a `Shape+` is dispatched through a
  #   unit of its own, `Shape+^Shape#twice`, and the producer emits the ones
  #   its own program dispatched virtually;
  # * the **parameter** — `doubled(shape : Shape)` was asked for as
  #   `doubled<Shape+>`.
  #
  # `Factory` is a module nested in an exported struct, which is the other
  # half: a nested type's travelling body is keyed on the path the renderer
  # looks it up under, and keyed on the bare name it was recorded and never
  # rendered — so the body did not travel however loudly this rule asked
  # for it.
  #
  # `std/io` and `std/xml` were the two the library had, and the link named
  # the line each time.
  it "carries the body of a method whose signature is wider than its callers" do
    with_tempdir("iyimod_widened_signature") do
      Dir.mkdir_p "boot"
      File.write "boot/shape.iyi", <<-IYI
        module boot/shape

        pub abstract class Shape
          pub abstract def area : Int32

          pub def twice : Int32
            area * 2
          end
        end

        pub class Square < Shape
          @side : Int32

          def initialize(@side : Int32)
          end

          pub def area : Int32
            @side * @side
          end
        end

        pub struct Make
          module Factory
            def self.square(side : Int32) : Shape
              Square.new(side)
            end

            def self.doubled(shape : Shape) : Int32
              shape.twice
            end
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/shape

        shape = Boot::Shape::Make::Factory.square(3)
        puts shape.twice
        puts Boot::Shape::Make::Factory.doubled(shape)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "18\n18"

      # The nested module's bodies are keyed under the path the renderer
      # reads them back by, not under its bare name.
      keys = Iyi::IyiMod.read(File.join("mods", "boot", "shape.iyimod")).mono_bodies.keys
      keys.should contain "Make::Factory#self.doubled(shape : Shape)"
      keys.should contain "Shape#twice()"

      File.delete "boot/shape.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "18\n18"
    end
  end

  # A module whose methods have no unit of their own, in the two shapes a
  # module gets them that way.
  #
  # Codegen files an instance method under the type that *includes* the
  # module, and files a generic's method under the instantiation. Include a
  # module into a type this module declares and the result is in this
  # module's object code; include it into `::Object` and the result is in
  # the prelude's, which is not this module's to ship. A generic nested
  # inside an exported module is the same gap reached the other way: the
  # exported path already knew a generic's bodies travel and the carried
  # path, which is where a nested type goes, did not ask.
  #
  # `std/colorize` is both at once and nothing else — `class ::Object;
  # include ObjectExtensions; end` over a `Colorize::Object(T)` — so a
  # consumer reading it from its artifact was told `undefined method
  # 'colorize' for String`, and once that was found, `undefined reference
  # to Object(String)^Object(T)#to_s`.
  it "carries the bodies of a module it included into a type it does not own" do
    with_tempdir("iyimod_stencilled_module") do
      Dir.mkdir_p "boot"
      File.write "boot/loud.iyi", <<-IYI
        module boot/loud

        pub struct Loud
          # Nested rather than exported, which is the shape that went
          # missing: the exported path knew a generic's bodies travel.
          struct Wrap(T)
            @value : T

            def initialize(@value : T)
            end

            def shout : String
              @value.to_s + "!"
            end
          end

          module Extensions
            def loud : String
              Wrap.new(self).shout
            end
          end
        end

        class ::Object
          include Boot::Loud::Loud::Extensions
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/loud

        puts "hi".loud
        puts 42.loud
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "hi!\n42!"

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "loud.iyimod"))
      # The include itself, which is the whole of what this module does to
      # `::Object` and carries no def of its own.
      artifact.reopened.find { |decl| decl.name == "::Object" }
        .try(&.includes).should eq ["::Boot::Loud::Loud::Extensions"]
      # The body of the method that include installs, which is compiled
      # once per including type and so never into this module's own code.
      artifact.mono_bodies.keys.should contain "Loud::Extensions#loud()"
      # And the nested generic's, which the carried path did not ask for.
      artifact.mono_bodies.keys.should contain "Loud::Wrap#shout()"

      File.delete "boot/loud.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "hi!\n42!"
    end
  end

  # A type the module declares under a name outside its own namespace.
  #
  # The reopened section was written for what a module *adds* to somebody
  # else's type — `12.gcd` on `::Int32` — and carried the methods and
  # nothing else, which is all an addition is. But a module may also
  # *declare* a type there: `struct ::BitArray` is the whole of
  # `std/bit_array`, `class ::File` holds the `enum Type` and the
  # `@@temp_counter` that `std/file` wrote, and then the methods are not
  # the whole of it. What the consumer cannot infer is the state — the
  # fields, the class variable, the members — and what it cannot resolve
  # is a name the file brought in with an import written *inside* the
  # type, which the unit's own imports do not reach.
  #
  # One program, because that is how it was found: each fix uncovered the
  # next on the same module. `can't infer the type of instance variable
  # '@size' of BitArray`, then `enum ::File::Type must have at least one
  # member`, then `undefined constant Path`, then `@@temp_counter : Type`,
  # then `undefined reference to File::Type#file?`.
  it "carries what a type it declares under a foreign name is made of" do
    with_tempdir("iyimod_foreign_declaration") do
      Dir.mkdir_p "boot"
      File.write "boot/tag.iyi", <<-IYI
        module boot/tag

        pub struct Tag
          @name : String

          def initialize(@name : String)
          end

          pub def name : String
            @name
          end
        end
        IYI
      File.write "boot/vault.iyi", <<-IYI
        module boot/vault

        import boot/tag::{Tag}

        struct ::Vault
          # The import above does not reach in here: a reopened name is not
          # lexically inside the unit, so the file writes a second one.
          import boot/tag::{Tag}

          @label : String
          @count : Int32

          @@made = 0_i64

          enum Kind : UInt8
            Small = 0
            Large = 1

            # By hand, which is what makes it the author's and not the
            # compiler's: the consumer generates its own from the members
            # and would never write this one.
            def small? : Bool
              value == 0_u8
            end
          end

          def initialize(@label : String, @count : Int32)
            @@made = @@made + 1_i64
          end

          def described(tag : Tag) : String
            tag.name + ":" + @label
          end

          def kind : Kind
            @count > 10 ? Kind::Large : Kind::Small
          end

          def self.made : Int64
            @@made
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/vault
        import boot/tag

        vault = Vault.new("box", 3)
        puts vault.described(Boot::Tag::Tag.new("t"))
        puts vault.kind.small?
        puts Vault.made
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "t:box\ntrue\n1"

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "vault.iyimod"))
      vault = artifact.reopened.find { |decl| decl.name == "::Vault" }.should_not be_nil
      vault.fields.map(&.[0]).should eq ["@label", "@count"]
      vault.class_vars.map(&.name).should eq ["@@made"]
      vault.usings.should eq ["boot/tag::{Tag}"]

      kind = artifact.reopened.find { |decl| decl.name == "::Vault::Kind" }.should_not be_nil
      kind.members.should eq [{"Small", "0_u8"}, {"Large", "1_u8"}]
      # Its unit is named after `::Vault::Kind`, which is not under this
      # module's namespace and so is not this module's to ship.
      artifact.mono_bodies.keys.should contain "::Vault::Kind#small?()"

      File.delete "boot/vault.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "t:box\ntrue\n1"
    end
  end

  # An impl written inside the type it targets.
  #
  # R-3 asks that an impl live in the module that defines the trait or the
  # module that defines the type, and a declaration's module is the type
  # enclosing it. Write `impl Show for Inner` inside `struct Outer` and the
  # enclosing type is `Outer`, which is where the rule wants it; render it
  # back at the module's own level — which is where the artifact writes
  # every impl — and the enclosing type is the module, so the consumer
  # refused a module that had already been checked.
  #
  # The rule is about who may *write* an impl. What arrives from an
  # artifact is the record of a check the producer passed, so it is not
  # asked again. `std/semantic_version` is the module this was found on.
  it "accepts an impl the producer wrote inside the type it targets" do
    with_tempdir("iyimod_impl_in_type") do
      Dir.mkdir_p "boot"
      File.write "boot/shown.iyi", <<-IYI
        module boot/shown

        pub trait Show
          abstract def show : String
        end
        IYI
      File.write "boot/pair.iyi", <<-IYI
        module boot/pair

        import boot/shown::{Show}

        pub struct Pair
          pub struct Half
            @value : Int32

            def initialize(@value : Int32)
            end

            pub def show : String
              "half " + @value.to_s
            end
          end

          impl Show for Half
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/pair
        import boot/shown

        def announce(item : Boot::Shown::Show) : String
          item.show
        end

        puts announce(Boot::Pair::Pair::Half.new(2))
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "half 2"

      File.delete "boot/pair.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "half 2"
    end
  end

  # A `run` inside a macro that travelled.
  #
  # `run` compiles and executes a program at the consumer's compile time,
  # and the module names that program the way the file that wrote the
  # macro could: `std/eiy` writes `run("./eiy/process", …)`, which is
  # beside `src/std/eiy.iyi`. Resolved against the artifact the consumer
  # read it from, that was `can't find "./eiy/process" relative to
  # "mods/std"`.
  #
  # No artifact can carry the program — it is a program, compiled and
  # executed there — so what travels is where the module was, which is
  # right whenever the producer's tree is present and an honest error when
  # it is not.
  it "resolves a travelling macro's run against the module's own directory" do
    with_tempdir("iyimod_macro_run") do
      Dir.mkdir_p "boot/tools"
      File.write "boot/tools/emit.iyi", <<-IYI
        module boot/tools/emit

        print "42"
        IYI
      File.write "boot/gen.iyi", <<-IYI
        module boot/gen

        pub macro answer
          {{ run("./tools/emit") }}
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/gen

        puts Boot::Gen.answer
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      # The module's own source goes; the program its macro runs stays,
      # because that is what `run` needs and what nothing can carry.
      File.delete "boot/gen.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "42"
    end
  end

  # `@[Primitive]`, in the two places it decides something.
  #
  # On a *type* it chooses what the compiler creates: `@[Primitive(
  # :ReferenceStorageType)] struct ReferenceStorage(T) < Value` is the
  # type whose size is the instance size of its parameter, not the struct
  # its declaration looks like. Without the annotation the consumer built
  # an ordinary struct, and `sizeof(ReferenceStorage(T))` answered its own
  # field's width.
  #
  # On a *def* it is the body. A def read from an artifact is a header —
  # its body is elsewhere, and codegen keys it on the type that declared
  # it — but an instruction has no elsewhere: it is compiled here, per
  # receiver. `std/reference_storage` writes `@[Primitive(:pre_initialize)]`
  # on `class ::Reference`, so every `Point.unsafe_construct` in the
  # consumer called one symbol compiled for `Reference` and got back a
  # pointer into nothing. It linked and ran, which is the way this design
  # can be wrong quietly rather than loudly.
  it "carries what an annotation decides, on a type and on a def" do
    with_tempdir("iyimod_primitive_annotation") do
      File.write "main.iyi", <<-IYI
        @[Unsafe("builds a Point in ReferenceStorage it allocates uninitialized")]
        module main

        import std/reference_storage::{ReferenceStorage}

        class Point
          getter x : Int32

          def initialize(@x : Int32)
          end
        end

        storage = uninitialized ReferenceStorage(Point)
        point = Point.unsafe_construct(pointerof(storage), 7)
        puts sizeof(ReferenceStorage(Point)) == instance_sizeof(Point)
        puts pointerof(storage).address == point.object_id
        puts storage.to_reference.x
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "true\ntrue\n7"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "true\ntrue\n7"
    end
  end

  # A `lib` the module declares, and the `struct` inside it.
  #
  # A `fun` is not a symbol this artifact answers for — the system linker
  # resolves `getpid` against libc — so for a long time nothing here
  # carried one and nothing missed it. A body that *travels* changes
  # that: the consumer compiles it and makes the call itself, so it needs
  # the declaration to make it with. `std/dir` calls `LibC.opendir` from
  # a body it ships and `std/file` types a field `LibC::Stat`, and both
  # were dropped whole — a `LibType` is a `ModuleType` and not a
  # `ClassType`, so it fell through every branch the emitter had.
  #
  # Found on darwin and nowhere else, because the `lib` those two declare
  # is inside `{% if flag?(:darwin) %}`. The gate reads its own artifacts
  # for four targets' front ends now, which is where a platform differs.
  it "carries a lib it declares, with the struct inside it" do
    with_tempdir("iyimod_own_lib") do
      Dir.mkdir_p "boot"
      File.write "boot/clock.iyi", <<-IYI
        @[Unsafe("declares the C clock library")]
        module boot/clock

        lib LibC
          struct Span
            seconds : Int64
            nanos : Int64
          end

          # ANSI C, so the link finds it on every platform this runs on.
          fun abs(value : Int32) : Int32
        end

        pub def with_abs(&block : Int32 -> Bool) : Bool
          block.call(LibC.abs(-3))
        end

        pub def span_seconds(span : LibC::Span) : Int64
          span.seconds
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/clock

        span = Boot::Clock::LibC::Span.new
        span.seconds = 3_i64
        puts Boot::Clock.span_seconds(span)
        puts Boot::Clock.with_abs { |value| value == 3 }
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "3\ntrue"

      artifact = Iyi::IyiMod.read(File.join("mods", "boot", "clock.iyimod"))
      lib_decl = artifact.exports.types.find { |decl| decl.name == "LibC" }.should_not be_nil
      lib_decl.kind.should eq "lib"
      lib_decl.funs.should eq ["fun abs(value : Int32) : Int32"]
      # The struct travels with it and its accessors do not: inside a
      # `lib` those are the compiler's.
      span = lib_decl.types.find { |decl| decl.name == "Span" }.should_not be_nil
      span.methods.should be_empty
      span.fields.map(&.[0]).should eq ["@seconds", "@nanos"]

      File.delete "boot/clock.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "3\ntrue"
    end
  end

  # An impl method written wider than what its body answers.
  #
  # An impl defines methods on its target, so when the target is a type
  # this module declares their machine code is in this module's own unit
  # and the header is all that has to travel. That holds while the symbol
  # on both sides is the same name, and a union is where it is not: a
  # consumer keys the call on the declaration and codegen keys the symbol
  # on the type the body inferred.
  #
  # The `calc` sample is the one this was found on — `impl Node for
  # Number` answers `Int32` under a `def evaluate(scope) : Int32 |
  # UnknownName | DividedByZero` — and it is a sample
  # `bench/samples_roundtrip.sh` did not cover, because that gate named
  # six of the twelve samples that import a module. It names all twelve
  # now.
  it "carries an impl method whose declaration is wider than its body" do
    with_tempdir("iyimod_impl_widened") do
      Dir.mkdir_p "boot"
      File.write "boot/eval.iyi", <<-IYI
        module boot/eval

        pub struct Missing
          pub def why : String
            "missing"
          end
        end

        pub trait Node
          abstract def value : Int32 | Missing
        end

        pub struct Literal
          @number : Int32

          def initialize(@number : Int32)
          end
        end

        impl Node for Literal
          def value : Int32 | Missing
            @number
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import boot/eval

        def answer(node : Boot::Eval::Node) : String
          result = node.value
          if result.is_a?(Int32)
            result.to_s
          else
            result.why
          end
        end

        puts answer(Boot::Eval::Literal.new(7))
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "7"

      File.delete "boot/eval.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "7"
    end
  end

  it "round-trips a module's initialiser" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "boot/config",
        source_path: "/src/boot/config.iyi",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
        initialiser: %(puts("one")\nputs("two")),
      )
      Iyi::IyiMod.write artifact, path

      Iyi::IyiMod.read(path).initialiser.should eq %(puts("one")\nputs("two"))
    end
  end

  it "round-trips the hashes" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "app/box",
        source_path: "/src/app/box.iyi",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
        hashes: Iyi::IyiMod::Hashes.new("iface", "impl", "src"),
      )
      Iyi::IyiMod.write artifact, path

      read = Iyi::IyiMod.read(path).hashes
      read.interface.should eq "iface"
      read.implementation.should eq "impl"
      read.source.should eq "src"
    end
  end

  # The property IV.3 exists for, and the one that decides whether the artifact
  # buys anything: **a body edit must not move the interface hash.** If it does,
  # every dependent re-typechecks for every edit and an incremental build is a
  # slower first build.
  it "moves the interface hash for a signature and not for a body" do
    with_tempdir("iyimod_hashes") do
      Dir.mkdir_p "app"
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.twice(21)
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      write_box = ->(body : String, extra : String) do
        File.write "app/box.iyi", <<-IYI
          module app/box

          pub def twice(n : Int32) : Int32
            #{body}
          end
          #{extra}
          IYI
      end

      emit = -> do
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.emit_iyimod = "mods"
        compiler.no_codegen = true
        compiler.compile source, "unused"
        Iyi::IyiMod.read(File.join("mods", "app", "box.iyimod")).hashes
      end

      write_box.call("n + n", "")
      before = emit.call

      # The same module, one body written differently.
      write_box.call("n * 2", "")
      after_body = emit.call

      after_body.interface.should eq before.interface
      after_body.implementation.should eq before.implementation
      after_body.source.should_not eq before.source

      # And a name added to the surface, which every dependent does have to
      # hear about.
      write_box.call("n * 2", <<-IYI)

        pub def thrice(n : Int32) : Int32
          n * 3
        end
        IYI
      after_signature = emit.call

      after_signature.interface.should_not eq after_body.interface
    end
  end

  # An artifact is a cache, so it is read only while it still describes its
  # module. Before the hashes it was read whichever way the source had moved,
  # and a build could compile against a surface nobody had and link code
  # nobody wrote — silently, with an exit status of nought.
  it "reads an artifact only while it still describes its module" do
    with_tempdir("iyimod_stale") do
      Dir.mkdir_p "app"
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.twice(21)
        IYI
      File.write "app/box.iyi", <<-IYI
        module app/box

        pub def twice(n : Int32) : Int32
          n + n
        end
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "42"

      File.write "app/box.iyi", <<-IYI
        module app/box

        pub def twice(n : Int32) : Int32
          n * 3
        end
        IYI

      # A build that only reads artifacts is refused, and told what moved.
      reader = create_spec_compiler
      reader.prelude = "iyi/prelude"
      reader.use_iyimod = "mods"
      expect_raises(Iyi::TypeException, /has changed since it was written/) do
        reader.compile source, File.expand_path("stale")
      end

      # A build that also writes them is the incremental loop: the module is
      # compiled from its source and its artifact rewritten.
      rewriter = create_spec_compiler
      rewriter.prelude = "iyi/prelude"
      rewriter.use_iyimod = "mods"
      rewriter.emit_iyimod = "mods"
      rewriter.compile source, File.expand_path("rebuilt")
      `./rebuilt`.chomp.should eq "63"

      # And what it wrote is read again without a word.
      again = create_spec_compiler
      again.prelude = "iyi/prelude"
      again.use_iyimod = "mods"
      again.compile source, File.expand_path("cached")
      `./cached`.chomp.should eq "63"
    end
  end

  # The remedy for a stale artifact compiles the module from its source. With
  # the source gone that is not a remedy, and a build that had passed
  # --emit-iyimod was still told to pass it.
  it "does not offer --emit-iyimod for an artifact with no source to rebuild from" do
    with_tempdir("iyimod_stale_no_source") do
      Dir.mkdir_p "app"
      File.write "main.iyi", <<-IYI
        module main

        import app/half

        puts App::Half.half(3.0)
        IYI
      File.write "app/half.iyi", <<-IYI
        module app/half

        import std/float

        pub def half(x : Float64) : Float64
          x / 2
        end
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      # Only the module's own artifact, without the `std/float` one it was
      # compiled against, and without its source.
      Dir.mkdir_p "only/app"
      File.copy "mods/app/half.iyimod", "only/app/half.iyimod"
      File.delete "app/half.iyi"

      rewriter = create_spec_compiler
      rewriter.prelude = "iyi/prelude"
      rewriter.use_iyimod = "only"
      rewriter.emit_iyimod = "only"
      error = expect_raises(Iyi::TypeException, /"std\/float", which it imports, has: there is no artifact for it/) do
        rewriter.compile source, File.expand_path("rewritten")
      end
      error.message.to_s.should contain %("app/half" has no source here to compile in its place)
      error.message.to_s.should_not contain "pass --emit-iyimod to this build"
    end
  end

  # A module path is a file path (R-1), so the same name can come to mean a
  # different file: `src/std/` ships a `std/text`, and a program with one of
  # its own that deletes it finds the library's at that path. The artifact is
  # then not stale — it is about a file nobody asked for — and saying
  # "src/std/text.iyi has changed since it was written" named a library file
  # the author has never opened.
  it "names a module whose path reaches another file now" do
    with_tempdir("iyimod_moved_name") do
      Dir.mkdir_p "std"
      File.write "std/text.iyi", <<-IYI
        module std/text

        pub def mine : Int32
          7
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/text::{mine}

        puts mine
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "7"

      File.delete "std/text.iyi"

      reader = create_spec_compiler
      reader.prelude = "iyi/prelude"
      reader.use_iyimod = "mods"
      # The module path is posix by grammar (R-1); the *file* it named is
      # printed the way this platform writes a path, so the expectation asks
      # for the file by its own separator rather than by a literal slash.
      moved = Regex.escape(File.join("std", "text.iyi"))
      expect_raises(Iyi::TypeException, /"std\/text" is .+ now, and this was written from .+#{moved}/) do
        reader.compile source, File.expand_path("moved")
      end
    end
  end

  # An artifact records the module it was written for, and nothing compared that
  # to the module being imported. A `.iyimod` copied onto another module's path
  # was adopted: its declarations were spliced in under its own name, and the
  # module actually asked for stayed undefined. The failure surfaced at the
  # first `using` (the keyword `import X::{...}` replaced) as "can't find
  # module 'm1/a'", which sends the reader off to write `m1/a.iyi` when the
  # file was there, valid, and already read.
  it "refuses an artifact that declares a different module" do
    with_tempdir("iyimod_module_name") do
      Dir.mkdir_p "m1"
      File.write "m1/a.iyi", <<-IYI
        module m1/a

        pub def v : Int32
          1
        end
        IYI
      File.write "m1/b.iyi", <<-IYI
        module m1/b

        pub def v : Int32
          2
        end
        IYI
      File.write "usea.iyi", <<-IYI
        module usea

        import m1/a::*

        puts v
        IYI
      File.write "useb.iyi", <<-IYI
        module useb

        import m1/b::*

        puts v
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("usea.iyi"), File.read("usea.iyi"))

      # Both artifacts, each written for the module it names.
      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-a")
      `./from-a`.chomp.should eq "1"

      other = Iyi::Compiler::Source.new(File.expand_path("useb.iyi"), File.read("useb.iyi"))
      producer_b = create_spec_compiler
      producer_b.prelude = "iyi/prelude"
      producer_b.emit_iyimod = "mods"
      producer_b.compile other, File.expand_path("from-b")
      `./from-b`.chomp.should eq "2"

      # The sources go away, so the artifacts are all there is. That is what
      # puts the mismatch beyond reach of every other check: with `m1/a.iyi`
      # present, the source hash catches the wrong file and blames the source
      # for having changed, which is a misdiagnosis of its own.
      Dir.mkdir_p "away"
      File.rename "m1", File.join("away", "m1")

      # `m1/b`'s artifact under `m1/a`'s name. Every checksum in it is intact and
      # the only thing wrong with it is which module it is.
      File.copy File.join("mods", "m1", "b.iyimod"), File.join("mods", "m1", "a.iyimod")

      reader = create_spec_compiler
      reader.prelude = "iyi/prelude"
      reader.use_iyimod = "mods"
      ex = expect_raises(Iyi::TypeException, /declares module "m1\/b", not "m1\/a"/) do
        reader.compile source, File.expand_path("mismatched")
      end

      # The file, so the reader knows which one to go and look at.
      ex.message.to_s.should contain File.join("mods", "m1", "a.iyimod")

      # At the `import`, which is where the artifact is read, and not at its
      # scope half, where the old misdiagnosis landed.
      ex.line_number.should eq 3
      ex.message.to_s.should_not match(/can't find module/)

      # A build that also writes artifacts repairs it once the source is back:
      # the module is compiled from it and the wrong file written over.
      File.rename File.join("away", "m1"), "m1"
      rewriter = create_spec_compiler
      rewriter.prelude = "iyi/prelude"
      rewriter.use_iyimod = "mods"
      rewriter.emit_iyimod = "mods"
      rewriter.compile source, File.expand_path("repaired")
      `./repaired`.chomp.should eq "1"
      Iyi::IyiMod.read_summary(File.join("mods", "m1", "a.iyimod"))
        .module_name.should eq "m1/a"

      # And what it wrote is read again without a word.
      again = create_spec_compiler
      again.prelude = "iyi/prelude"
      again.use_iyimod = "mods"
      again.compile source, File.expand_path("cached")
      `./cached`.chomp.should eq "1"
    end
  end

  # IV.3's whole point, in the shape that shows it: two programs over one graph,
  # so that a dependency can be rebuilt while a dependent is not touched. A body
  # edit under `app/outer` must leave its artifact valid; a surface edit must
  # not.
  it "keeps a dependent whose dependency changed only a body" do
    with_tempdir("iyimod_interface_hash") do
      Dir.mkdir_p "app"
      File.write "main.iyi", <<-IYI
        module main

        import app/outer

        puts App::Outer.outer
        IYI
      File.write "leaf.iyi", <<-IYI
        module leaf

        import app/inner

        puts App::Inner.inner
        IYI
      File.write "app/outer.iyi", <<-IYI
        module app/outer

        import app/inner

        pub def outer : Int32
          App::Inner.inner + 41
        end
        IYI
      write_inner = ->(body : String, extra : String) do
        File.write "app/inner.iyi", <<-IYI
          module app/inner

          pub def inner : Int32
            #{body}
          end
          #{extra}
          IYI
      end

      main = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      leaf = Iyi::Compiler::Source.new(File.expand_path("leaf.iyi"), File.read("leaf.iyi"))

      build = ->(program : Iyi::Compiler::Source, output : String, emit : Bool) do
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.use_iyimod = "mods"
        compiler.emit_iyimod = "mods" if emit
        compiler.compile program, File.expand_path(output)
      end

      write_inner.call("1", "")
      build.call(main, "first", true)
      `./first`.chomp.should eq "42"

      # The other program rewrites `app/inner`'s artifact and leaves
      # `app/outer`'s where it was.
      write_inner.call("2", "")
      build.call(leaf, "leaf-build", true)

      # So `app/outer` is read from its artifact: the module it was compiled
      # against hashes the same on its surface, and its new body arrives as
      # machine code through the linker.
      build.call(main, "kept", false)
      `./kept`.chomp.should eq "43"

      # A name added to that surface is a different matter.
      write_inner.call("2", <<-IYI)

        pub def other : Int32
          3
        end
        IYI
      build.call(leaf, "leaf-again", true)

      expect_raises(Iyi::TypeException, /the surface of "app\/inner"/) do
        build.call(main, "invalidated", false)
      end
    end
  end

  it "round-trips the types a module numbers" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "app/box",
        source_path: "/src/app/box.iyi",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
        type_ids: ["Array(App::Box::Item)", "Pointer(App::Box::Item)"],
      )
      Iyi::IyiMod.write artifact, path

      Iyi::IyiMod.read(path).type_ids.should eq ["Array(App::Box::Item)", "Pointer(App::Box::Item)"]
    end
  end
  # GC_DESIGN.md Stage 1: the pointer maps. The container examples check the
  # encoding and the refusals; the compiling example is the one that proves
  # the pass, because it asserts the offsets against the layout the compiler
  # itself computed rather than against numbers typed from memory.
  describe "layouts" do
    it "round-trips them" do
      layouts = [
        {"App::Shapes::Point", Iyi::IyiMod::TypeLayout.new(41, 8_u32, 8_u32, [] of UInt32, [] of UInt32)},
        {"App::Shapes::Labelled", Iyi::IyiMod::TypeLayout.new(8, 40_u32, 36_u32, [8_u32, 24_u32], [] of UInt32)},
      ]
      with_temporary_file do |path|
        Iyi::IyiMod.write sample_artifact(layouts: layouts), path
        Iyi::IyiMod.read(path).layouts.should eq layouts
      end
    end

    it "is refused when its bytes changed under it, like every other section" do
      with_temporary_file do |path|
        # With no object code after it, the layouts payload is the last bytes
        # of the file, so the last byte is this section's own.
        Iyi::IyiMod.write sample_artifact(layouts: [
          {"App::Shapes::Labelled", Iyi::IyiMod::TypeLayout.new(8, 40_u32, 36_u32, [8_u32, 24_u32], [] of UInt32)},
        ]), path
        bytes = File.read(path).to_slice.dup
        bytes[bytes.size - 1] ^= 0xFF_u8
        File.write(path, bytes)

        expect_raises(Iyi::IyiMod::Error, /the Layouts section is damaged/) do
          Iyi::IyiMod.read(path)
        end
      end
    end

    it "shows them in mod dump, in a form to check against the struct as written" do
      io = IO::Memory.new
      Iyi::IyiMod.dump sample_artifact(layouts: [
        {"App::Shapes::Labelled", Iyi::IyiMod::TypeLayout.new(8, 40_u32, 36_u32, [8_u32, 24_u32], [] of UInt32)},
      ]), io
      text = io.to_s

      text.should contain "layouts"
      text.should contain "App::Shapes::Labelled: type id 8, 40 bytes (scan cap 36), scan [8, 24], noscan []"
    end

    it "computes the offsets from the emitted struct, not from field sizes added up" do
      with_tempdir("iyimod_layouts") do
        Dir.mkdir_p "app"
        File.write "app/shapes.iyi", <<-IYI
          module app/shapes

          pub struct Point
            @x : Int32
            @y : Int32

            def initialize(@x : Int32, @y : Int32)
            end
          end

          pub struct Inner
            @ref : String
            @n : Int32

            def initialize(@ref : String, @n : Int32)
            end
          end

          pub struct Outer
            @inner : Inner
            @flag : Bool

            def initialize(@inner : Inner, @flag : Bool)
            end
          end

          pub class Labelled
            @name : String
            @point : Point
            @tags : Array(String)
            @count : Int32

            def initialize(@name : String, @point : Point, @tags : Array(String), @count : Int32)
            end
          end

          pub class Base
            @id : Int64
            @owner : String

            def initialize(@id : Int64, @owner : String)
            end
          end

          pub class Derived < Base
            @extra : String

            def initialize(id : Int64, owner : String, @extra : String)
              super(id, owner)
            end
          end

          pub struct Box(T)
            @value : T

            def initialize(@value : T)
            end
          end

          pub struct Unused(T)
            @value : T

            def initialize(@value : T)
            end
          end

          pub def make(name : String) : Labelled
            Box(String).new("packed")
            Labelled.new(name, Point.new(1, 2), ["t"], 3)
          end
          IYI
        File.write "main.iyi", <<-IYI
          module main

          import app/shapes

          App::Shapes.make("hi")
          puts "ok"
          IYI

        captured = nil
        compiler = create_spec_compiler
        compiler.prelude = "iyi/prelude"
        compiler.emit_iyimod = "mods"
        source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
        compiler.compile_configure_program(source, File.expand_path("from-source")) do |program|
          captured = program
        end
        `./from-source`.chomp.should eq "ok"

        program = captured.not_nil!
        artifact = Iyi::IyiMod.read(File.join("mods", "app", "shapes.iyimod"))
        shapes = program.types["App"].types["Shapes"]

        # The layout the compiler computed, asked the way `offsetof` asks it.
        # An assertion against numbers typed from memory would prove nothing:
        # the padding in these types is the target's decision.
        offset_of = ->(type : Iyi::Type, name : String) do
          index = type.index_of_instance_var(name).not_nil!
          if type.struct?
            program.offset_of(type, index)
          else
            program.instance_offset_of(type, index)
          end
        end
        layout_of = ->(name : String) do
          entry = artifact.layouts.find { |(candidate, _)| candidate == name }
          entry.should_not be_nil
          entry.not_nil![1]
        end

        # A type with no pointer fields is present with an empty map, not
        # absent: absent means "no layout, scan conservatively" to a
        # collector, and this type has a layout with nothing to scan.
        point = shapes.types["Point"]
        point_layout = layout_of.call("App::Shapes::Point")
        point_layout.scan_offsets.should eq [] of UInt32
        point_layout.alloc_size.should eq program.instance_size_of(point).to_u32

        inner = shapes.types["Inner"]
        inner_layout = layout_of.call("App::Shapes::Inner")
        inner_layout.scan_offsets.should eq [offset_of.call(inner, "@ref").to_u32]
        inner_layout.alloc_size.should eq program.instance_size_of(inner).to_u32
        # The scan cap is the end of the last field, before tail padding.
        expected_cap = offset_of.call(inner, "@n") + program.size_of(program.int32)
        inner_layout.scan_cap.should eq expected_cap.to_u32

        # A struct field is stored inline, so its pointer words flatten into
        # the containing map: Outer's is where `@inner` sits plus where
        # `@ref` sits inside an Inner.
        outer = shapes.types["Outer"]
        outer_layout = layout_of.call("App::Shapes::Outer")
        outer_layout.scan_offsets.should eq [
          (offset_of.call(outer, "@inner") + offset_of.call(inner, "@ref")).to_u16,
        ]

        # A class carries its type id under the object, not in it, so its
        # first field is at 0; `@point` has no inner pointers and `@count`
        # is a scalar, so neither is here.
        labelled = shapes.types["Labelled"]
        labelled_layout = layout_of.call("App::Shapes::Labelled")
        labelled_layout.scan_offsets.should eq [
          offset_of.call(labelled, "@name").to_u16,
          offset_of.call(labelled, "@tags").to_u16,
        ]
        labelled_layout.alloc_size.should eq program.instance_size_of(labelled).to_u32

        # An inherited pointer field is in the subclass's own map, at the
        # offset the subclass's struct gives it.
        derived = shapes.types["Derived"]
        derived_layout = layout_of.call("App::Shapes::Derived")
        derived_layout.scan_offsets.should eq [
          offset_of.call(derived, "@owner").to_u16,
          offset_of.call(derived, "@extra").to_u16,
        ]

        # A generic the module owns contributes each instantiation this build
        # has, under the instantiation's own name; one it never instantiated
        # contributes nothing, because R-4's per-GC-shape keying does not
        # exist yet to give `Unused(T)` a shape of its own.
        box = shapes.types["Box"].as(Iyi::GenericType).instantiated_types
          .find { |instance| instance.to_s == "App::Shapes::Box(String)" }.not_nil!
        box_layout = layout_of.call("App::Shapes::Box(String)")
        box_layout.scan_offsets.should eq [offset_of.call(box, "@value").to_u32]
        artifact.layouts.find { |(name, _)| name.includes?("Unused") }.should be_nil

        # Empty everywhere, on purpose: what noscan means is Stage 6's to say.
        artifact.layouts.each do |(_, layout)|
          layout.noscan_offsets.should be_empty
          layout.type_id.should be > 0
        end
      end
    end
  end

  # An artifact with every declaration and no machine code is not the same
  # thing as one that legitimately has none: an `abstract class` with no
  # subclass in its own shard carries no object code and is complete, while a
  # boundary whose fill build died carries none and promises everything. Read as
  # it stands the second is a hundred undefined symbols with the cause named
  # nowhere.
  it "refuses a boundary whose object-code step never finished" do
    with_tempdir("iyimod_unfilled") do
      Dir.mkdir_p "app"
      File.write "app/counter.iyi", <<-IYI
        module app/counter

        pub def total : Int32
          42
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/counter

        puts App::Counter.total
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      # Written back as the fill step would have left it had the build died:
      # everything it declares, and no record of having finished.
      path = File.join("mods", "app", "counter.iyimod")
      artifact = Iyi::IyiMod.read(path, want_object_code: true)
      artifact.filled.should be_true
      artifact.filled = false
      Iyi::IyiMod.write artifact, path

      File.delete "app/counter.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      expect_raises(Iyi::TypeException, /was never filled: `iyi tool bind` wrote its declarations/) do
        consumer.compile source, File.expand_path("from-artifact")
      end
    end
  end

  # The flag beside the name, because the consumer cannot work it out. A unit
  # that reads a class variable with a live initialiser calls
  # `~Owner::name:read`; one reading a variable without an initialiser reads the
  # global. Assume the first and an iyi-prelude program dies on
  # `BUG: __crystal_once is not defined`; assume the second and a `--crystal`
  # build leaves `~Exception::CallStack::skip:read` undefined.
  # Two of them share a *name* and differ only in their owner, and that is the
  # case this list was once unable to hold: the bookkeeping behind it was keyed
  # on the variable, `MetaTypeVar` is a `Var`, and a `Var`'s equality is its
  # name. A class variable declared on a superclass is copied onto every
  # subclass that reads one, so `bindata`'s `@@bit_fields` is six variables and
  # was one key — the last write took the entry and the link ended on
  # `~ASN1::BER::bit_fields:read`.
  #
  # `Requires` says what a consumer has to have compiled and this says what it
  # has to have linked against, and the consumer cannot derive one from the
  # other: it replays `require "yaml"`, so it *has* `lib LibYAML` and its
  # `@[Link("yaml")]`, and drops the flag anyway — a flag is collected from the
  # libs that build marked `used?`, and the call to `yaml_parser_parse` is in
  # an object file it reads rather than compiles.
  # A redefinition and the definition it replaced are two bodies under one
  # signature, and `previous_def` is how the second reaches the first. `db`
  # writes a macro that redefines `around_query_or_exec` that way, and keyed on
  # the signature alone the second body took the first's place.
  it "tells a redefinition's body from the one it replaced" do
    signature = Iyi::IyiMod::Signature.new(
      name: "around_query_or_exec", receiver: "", parameters: ["args : Enumerable"],
      block_parameter: "&", return_type: "",
      free_variables: [] of String, required: false,
    )

    first = Iyi::IyiMod.mono_body_key("DB::Statement", signature, 0)
    second = Iyi::IyiMod.mono_body_key("DB::Statement", signature, 1)
    first.should_not eq second

    # And both sides count the same way, which is what makes a position a name.
    Iyi::IyiMod.mono_body_ordinals([signature, signature]).should eq [0, 1]
  end

  # An instance method and a class method of the same name and parameters are
  # two methods, and the key that finds a body again was missing the only thing
  # that tells them apart. `Log` has a `{% for %}` loop writing `def info(*,
  # exception : Exception)` on the instance and another writing `def self.info`
  # with the same parameters on the class; the second took the first's key, and
  # a consumer read `Log#info` as `Log#info` calling itself.
  it "tells a class method's body from an instance method's" do
    instance = Iyi::IyiMod::Signature.new(
      name: "info", receiver: "", parameters: ["exception : Exception"],
      block_parameter: "", return_type: "Nil",
      free_variables: [] of String, required: false,
    )
    on_class = instance.copy_with(receiver: "self")

    Iyi::IyiMod.mono_body_key("Log", instance)
      .should_not eq Iyi::IyiMod.mono_body_key("Log", on_class)
  end

  it "round-trips the libs a module's object code calls into" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "y_a_m_l",
        source_path: "/src/probe.cr",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
      )
      artifact.libs = ["LibC", "LibYAML"]
      Iyi::IyiMod.write artifact, path

      Iyi::IyiMod.read(path).libs.should eq ["LibC", "LibYAML"]
    end
  end

  it "round-trips how a unit refers to a class variable" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "app/box",
        source_path: "/src/app/box.iyi",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
        class_vars: [
          Iyi::IyiMod::ClassVarRef.new("App::Box::Store::@@cache", false),
          Iyi::IyiMod::ClassVarRef.new("App::Box::Crate::@@cache", false),
          Iyi::IyiMod::ClassVarRef.new("Exception::CallStack::@@skip", true),
        ],
      )
      Iyi::IyiMod.write artifact, path

      read = Iyi::IyiMod.read(path).class_vars
      read.map(&.name).should eq ["App::Box::Store::@@cache",
                                  "App::Box::Crate::@@cache",
                                  "Exception::CallStack::@@skip"]
      read.map(&.lazy).should eq [false, false, true]
    end
  end

  # The pattern and not just the name, because the name is a digest of the
  # pattern and a digest does not read backwards. `Constants` carries a name
  # because for every other constant a name is enough — the consumer's own
  # library has it, or the module's initialiser assigns it. Nobody wrote this
  # one and `$` keeps it out of the source channel, so what a consumer needs to
  # build it travels here or nowhere.
  it "round-trips what a synthesised regex constant was made from" do
    with_temporary_file do |path|
      artifact = Iyi::IyiMod::Artifact.new(
        module_name: "app/box",
        source_path: "/src/app/box.cr",
        compiler_version: "1.22.0-dev+abc1234",
        target_triple: "x86_64-pc-linux-gnu",
        flags: ["bits64"],
        imports: [] of Iyi::IyiMod::ImportEdge,
        constants: ["$Regex:0efd0f2ede78a843db3048bc8d79fcff"],
        regexes: [Iyi::IyiMod::RegexConst.new("$Regex:0efd0f2ede78a843db3048bc8d79fcff",
          "alpha-[0-9]+", 1_u32)],
      )
      Iyi::IyiMod.write artifact, path

      read = Iyi::IyiMod.read(path).regexes
      read.size.should eq 1
      read[0].name.should eq "$Regex:0efd0f2ede78a843db3048bc8d79fcff"
      read[0].pattern.should eq "alpha-[0-9]+"
      read[0].options.should eq 1_u32
    end
  end

  # Same pattern, same name, in a program that never met the other one — which
  # is the whole of what the digest is for. Two boundaries numbering their own
  # literals from zero both said `$Regex:0`, and a consumer holding both can
  # only define one: the second module's machine code read the first module's
  # pattern, with nothing raised and nothing linked wrong.
  it "names a regex constant after the literal rather than the order it was met in" do
    alpha = Iyi::Program.regex_const_name("alpha-[0-9]+", Iyi::RegexOptions::None)
    beta = Iyi::Program.regex_const_name("beta-[a-z]+", Iyi::RegexOptions::None)

    alpha.should_not eq beta
    alpha.should eq Iyi::Program.regex_const_name("alpha-[0-9]+", Iyi::RegexOptions::None)

    # The flags are part of what the literal means, so they are part of its
    # name: `/a/i` and `/a/` are two patterns and must not share one constant.
    Iyi::Program.regex_const_name("a", Iyi::RegexOptions::IGNORE_CASE)
      .should_not eq Iyi::Program.regex_const_name("a", Iyi::RegexOptions::None)

    # Unwritable, which the old name already was and this one has to keep: the
    # consumer defines it, and a name a consumer could also *write* would be a
    # constant two things own.
    alpha.should start_with "$Regex:"
  end

  it "renders the initialiser inside the module it belongs to" do
    artifact = Iyi::IyiMod::Artifact.new(
      module_name: "boot/config",
      source_path: "/src/boot/config.iyi",
      compiler_version: "1.22.0-dev+abc1234",
      target_triple: "x86_64-pc-linux-gnu",
      flags: [] of String,
      imports: [] of Iyi::IyiMod::ImportEdge,
      initialiser: %(puts("hello")),
    )

    io = IO::Memory.new
    Iyi::IyiMod.declarations artifact, io
    text = io.to_s

    text.should start_with "module boot/config\n"
    text.should contain %(puts("hello"))
  end

  # A consumer allocates the type, and allocating needs its size. Without the
  # fields it read `pub struct Box` as a struct with none, and generated a
  # `Box::new` that allocated nothing while the module's own code wrote to
  # `@n` — memory corruption waiting for the rest of `ObjectCode` to stop
  # failing at link, rather than a missing feature.
  it "carries a type's fields" do
    with_tempdir("iyimod_fields") do
      Dir.mkdir_p "std"
      File.write "std/box.iyi", <<-IYI
        module std/box

        pub struct Box(T)
          @item : T
          @count : Int32

          def initialize(@item : T)
            @count = 1
          end

          def item : T
            @item
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/box

        puts Std::Box::Box(Int32).new(7).item
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, File.expand_path("unused")

      declaration = Iyi::IyiMod.read(File.join("mods", "std", "box.iyimod"))
        .exports.types.find! { |candidate| candidate.name == "Box" }

      # In the order they were declared, because that order is the layout: a
      # field's offset is its position in this list, and a consumer compiling a
      # body of this module's has to reach the same field the module's own
      # object code does. Global, the type parameter excepted: the declaration
      # is read inside the module (`IyiMod.absolute_type`).
      declaration.fields.should eq [{"@item", "T", ""}, {"@count", "::Int32", ""}]
    end
  end

  # SPEC.md III.4.4: the `Share` marker travels with the declaration. A
  # producer writes `@[Share]` above every type it found shareable, and a
  # consumer reads that — never recomputing, because the bodies that said
  # no method assigns a field are not in the artifact — and gates the block
  # `IyiThread.start` runs on another thread by it (III.4.11).
  it "carries a type's Share marker, and a consumer's thread reads it" do
    with_tempdir("iyimod_share") do
      Dir.mkdir_p "std"
      File.write "std/pair.iyi", <<-IYI
        module std/pair

        pub struct Pair
          @left : Int32
          @right : Int32

          def initialize(@left : Int32, @right : Int32)
          end

          def left : Int32
            @left
          end
        end

        pub class Counter
          @count : Int32

          def initialize
            @count = 0
          end

          def bump : Nil
            @count = 1
          end

          def count : Int32
            @count
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/pair

        pair = Std::Pair::Pair.new(1, 2)
        t = IyiThread.start do
          pair.left
          nil
        end
        t.join
        puts pair.left
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, File.expand_path("unused")

      types = Iyi::IyiMod.read(File.join("mods", "std", "pair.iyimod")).exports.types
      types.find! { |candidate| candidate.name == "Pair" }.annotations.should eq ["@[Share]"]
      types.find! { |candidate| candidate.name == "Counter" }.annotations.should eq [] of String

      File.delete "std/pair.iyi"

      # The shareable one crosses a thread from the artifact alone.
      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.no_codegen = true
      consumer.compile source, File.expand_path("unused")

      # The other is refused with the artifact as the reason: the consumer
      # cannot see `bump`, and does not pretend to.
      File.write "main.iyi", <<-IYI
        module main

        import std/pair

        counter = Std::Pair::Counter.new
        t = IyiThread.start do
          counter.count
          nil
        end
        t.join
        IYI
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      refusing = create_spec_compiler
      refusing.prelude = "iyi/prelude"
      refusing.use_iyimod = "mods"
      refusing.no_codegen = true
      expect_raises(Iyi::TypeException, /captures `counter : Std::Pair::Counter`, which is not Share: Std::Pair::Counter came from an artifact whose producer did not find it shareable/) do
        refusing.compile source, File.expand_path("unused")
      end
    end
  end

  # A private type is carried rather than exported, and wears the marker
  # all the same: a body that travels reaches it, and a consumer's reach
  # walk asks of it what it asks of an exported one. iyi-db's
  # `AROUND_HOOKS`, an `AroundHooks` of a `Mutex` and an `Atomic` read by
  # every query, arrived bare: built from db's artifacts, a plain spawn that
  # runs in parallel built from source stayed in its unit, and every
  # `spawn(unit: :new)` that queried was warned about it.
  it "carries a private type's Share marker, so a travelling body's reach sees it" do
    with_tempdir("iyimod_share_private") do
      Dir.mkdir_p "dep"
      File.write "dep/hooks.iyi", <<-IYI
        module dep/hooks

        class Hooks
          @count : Atomic(Int32)

          def initialize
            @count = Atomic(Int32).new(0)
          end

          def any? : Bool
            @count.get > 0
          end
        end

        class Tally
          @count : Int32

          def initialize
            @count = 0
          end

          def bump : Nil
            @count = 1
          end
        end

        HOOKS = Hooks.new

        pub def busy?(x : T) : Bool forall T
          HOOKS.any?
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import dep/hooks::{busy?}

        group do |g|
          g.spawn(unit: :new) { busy?(1) }
        end
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, File.expand_path("unused")
      producer.warnings.reports.should be_empty

      types = Iyi::IyiMod.read(File.join("mods", "dep", "hooks.iyimod")).exports.types
      types.find! { |candidate| candidate.name == "Hooks" }.annotations.should eq ["@[Share]"]
      types.find! { |candidate| candidate.name == "Tally" }.annotations.should eq [] of String

      File.delete "dep/hooks.iyi"

      # Read back from the artifact alone, `Hooks` is Share: the block that
      # reaches `HOOKS` through `busy?`'s body is not warned about.
      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.no_codegen = true
      consumer.compile source, File.expand_path("unused")
      consumer.warnings.reports.map(&.to_s).should eq [] of String
    end
  end

  # An owning type travels as one: read back as `@[Share]` alone it would be
  # Share only when its argument is, and `Guard(Counter)` - the escape the
  # marker exists for - would stop being Share at the artifact's edge.
  it "carries an owning type's Share marker, and a consumer's thread reads it" do
    with_tempdir("iyimod_share_owns") do
      Dir.mkdir_p "std"
      File.write "std/guard.iyi", <<-IYI
        @[Unsafe("a guard is trusted to cross threads under @[Share(owns: true)] because only its locked blocks reach the value")]
        module std/guard

        pub class Counter
          @count : Int32

          def initialize
            @count = 0
          end

          def bump : Nil
            @count = @count + 1
          end
        end

        @[Share(owns: true)]
        pub class Guard(T)
          @value : T

          def self.new(&block : -> U) : Guard(U) forall U
            Guard(U).build(block.call)
          end

          protected def self.build(value : T) : Guard(T)
            new(value)
          end

          private def initialize(@value : T)
          end

          def lock(&block : T -> _) : Nil
            block.call(@value)
            nil
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/guard::{Guard, Counter}

        guard = Guard.new { Counter.new }
        t = IyiThread.start do
          guard.lock { |counter| counter.bump }
          nil
        end
        t.join
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, File.expand_path("unused")

      types = Iyi::IyiMod.read(File.join("mods", "std", "guard.iyimod")).exports.types
      types.find! { |candidate| candidate.name == "Guard" }.annotations.should eq ["@[Share(owns: true)]"]

      File.delete "std/guard.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.no_codegen = true
      consumer.compile source, File.expand_path("unused")
    end
  end

  it "renders a type's fields into the declarations a consumer reads" do
    declaration = type_declaration("List", "generic struct",
      type_parameters: ["T"],
      fields: [{"@items", "Array(T)", ""}],
      methods: [signature("size", return_type: "Int32")])

    io = IO::Memory.new
    Iyi::IyiMod.declarations sample_artifact(types: [declaration]), io

    io.to_s.should contain "pub struct List(T)\n  @items : Array(T)\n"
  end

  # The other half of the rule above, and the half that went wrong three times.
  # A module whose top level is only declarations has no initialiser — and the
  # declarations do not look like declarations from the outside: the file is
  # wrapped in a `ModuleDef`, `pub struct` is a `VisibilityModifier` around one,
  # and `type Elem = T` is an `AssocTypeDecl`. Each of those, taken for
  # something that runs, refused a module that was fine.
  it "does not mistake declarations for an initialiser" do
    with_tempdir("iyimod_no_initialiser") do
      Dir.mkdir_p "std"
      File.write "std/hold.iyi", <<-IYI
        module std/hold

        pub trait Hold
          type Item

          abstract def item : Item
        end

        pub struct Box
          @n : Int32

          def initialize(@n : Int32)
          end
        end

        impl Hold for Box
          type Item = Int32

          def item : Int32
            @n
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import std/hold::{Hold}


        puts Std::Hold::Box.new(7).item
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      Iyi::IyiMod.read(File.join("mods", "std", "hold.iyimod")).has_initialiser.should be_false
    end
  end

  # A macro call is not code until it is expanded, and what a module's macros
  # expand to is mostly declarations. Reading the call itself made every module
  # that writes a `getter` read as having code in a type body and refused it,
  # which is the ordinary shape of a library rather than a corner of one.
  it "does not mistake a macro call in a type body for an initialiser" do
    with_tempdir("iyimod_macro_declarations") do
      Dir.mkdir_p "app"
      File.write "app/store.iyi", <<-IYI
        module app/store

        pub struct Item
          getter name : String
          getter price : Int32

          def initialize(@name : String, @price : Int32)
          end
        end

        pub class Store
          private record Entry,
            item : Item,
            count : Int32

          @entries : Array(Entry)

          def initialize
            @entries = Array(Entry).new
          end

          pub def add(name : String, price : Int32, count : Int32) : Nil
            @entries << Entry.new(Item.new(name, price), count)
          end

          pub def total : Int32
            sum = 0
            @entries.each { |entry| sum = sum + entry.item.price * entry.count }
            sum
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/store

        store = App::Store::Store.new
        store.add("a", 3, 2)
        store.add("b", 5, 1)
        puts store.total
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "11"

      Iyi::IyiMod.read(File.join("mods", "app", "store.iyimod")).has_initialiser.should be_false

      File.delete "app/store.iyi"

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "11"
    end
  end

  # And the other direction, which is what makes following the expansion safe:
  # a macro that expands to something that has to *run* is still code in a type
  # body, and a build that would generate against it is still refused.
  it "sees the code a macro expands to in a type body" do
    with_tempdir("iyimod_macro_code") do
      Dir.mkdir_p "app"
      File.write "app/thing.iyi", <<-IYI
        module app/thing

        pub class Thing
          {% for word in ["one"] %}
            puts {{ word }}
          {% end %}

          pub def n : Int32
            1
          end
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/thing

        puts App::Thing::Thing.new.n
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      Iyi::IyiMod.read(File.join("mods", "app", "thing.iyimod")).has_initialiser.should be_true

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      expect_raises(Iyi::TypeException, /has code inside a type body/) do
        consumer.compile source, File.expand_path("from-artifact")
      end
    end
  end

  # A build that generates no code has none to carry. Checked because the two
  # cases are told apart by the flag the build was given and by nothing in the
  # file, so an empty section here is the honest answer rather than a failure
  # to collect.
  it "carries no object code from a --no-codegen build" do
    with_tempdir("iyimod_no_codegen") do
      Dir.mkdir_p "app"
      File.write "app/greeter.iyi", <<-IYI
        module app/greeter

        pub def polite(name : String) : String
          "Hello, " + name
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/greeter

        puts App::Greeter.polite("world")
        IYI

      compiler = create_spec_compiler
      compiler.prelude = "iyi/prelude"
      compiler.emit_iyimod = "mods"
      compiler.no_codegen = true

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      compiler.compile source, "unused"

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "greeter.iyimod"),
        want_object_code: true)
      artifact.object_code.should be_empty
      artifact.exports.functions.map(&.name).should eq ["polite"]
    end
  end

  # An edge names a module, and it has to name one whichever way the module on
  # the far end arrived. The edges are kept by filename because load-once is,
  # so writing one out means looking the filename back up — and the lookup used
  # to ask only the modules read from source, which left an import resolved
  # from a `.iyimod` recorded as that file's path. `mods/app/inner.iyimod` is
  # this build's directory layout, not a module anybody else can resolve.
  it "records an import read from an artifact as the module it is" do
    with_tempdir("iyimod_artifact_edge") do
      Dir.mkdir_p "app"
      File.write "app/inner.iyi", <<-IYI
        module app/inner

        pub def inner : Int32
          1
        end
        IYI
      File.write "app/outer.iyi", <<-IYI
        module app/outer

        import app/inner

        pub def outer : Int32
          App::Inner.inner
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/outer

        puts App::Outer.outer
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.no_codegen = true
      producer.compile source, "unused"

      # Only the leaf keeps its artifact, so the second build reads `app/inner`
      # from a `.iyimod` and `app/outer` from source — which is the shape an
      # incremental build has, and the only one where the edge is written by a
      # module whose dependency did not come from source.
      File.delete File.join("mods", "app", "outer.iyimod")

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.emit_iyimod = "out"
      consumer.no_codegen = true
      consumer.compile source, "unused"

      artifact = Iyi::IyiMod.read(File.join("out", "app", "outer.iyimod"))
      artifact.import_names.should eq ["app/inner"]
    end
  end

  it "round-trips exported types with their parameters and methods" do
    declaration = type_declaration("List", "generic struct",
      type_parameters: ["T"],
      methods: [signature("at", ["index : Int32"], "T")])

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(types: [declaration]), path
      read = Iyi::IyiMod.read(path).exports.types

      read.size.should eq 1
      read[0].name.should eq "List"
      read[0].kind.should eq "generic struct"
      read[0].type_parameters.should eq ["T"]
      read[0].methods.map(&.name).should eq ["at"]
    end
  end

  # II.4 depends on this record: it is what lets a consumer answer "does
  # `Customer` implement `ToJSON`?" without reading `Customer`.
  it "round-trips impl records" do
    impls = [
      impl_record("Std::Traits::Cmp", "Int32"),
      impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"], assoc_types: [{"Elem", "T"}]),
    ]

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(impls: impls), path
      read = Iyi::IyiMod.read(path).exports.impls

      read.map(&.trait_name).should eq ["Std::Traits::Cmp", "Std::Enumerable::Enumerable"]
      read.map(&.type_name).should eq ["Int32", "Std::List::List(T)"]
      read[1].free_variables.should eq ["T"]
      read[1].assoc_types.should eq [{"Elem", "T"}]
    end
  end

  # A constructor's result is its type and nobody writes it down, so an absent
  # return type is recorded as absent rather than filled in with a guess.
  it "renders a signature with no return annotation without one" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(exports: [
      signature("initialize", ["items : Array(T)"]),
    ]), io

    io.to_s.should contain "  def initialize(items : Array(T))\n"
  end

  it "dumps a type declaration and an impl" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(
      types: [type_declaration("Greet", "trait",
        methods: [signature("greet", return_type: "String")])],
      impls: [impl_record("Greet", "User")],
    ), io
    text = io.to_s

    # With its visibility, because "carried and unreachable" is a thing a
    # reader of this file has to be able to tell from "carried and exported".
    text.should contain "  pub trait Greet"
    text.should contain "    def greet : String"
    text.should contain "  impl ::Greet for ::User"
  end

  # II.6 keeps a trait's parameters and its associated types apart — the first
  # is supplied at the `impl` line and the second is answered in its body — so
  # an artifact that merged them would ask for `Elem` in the one place II.6
  # says it does not go.
  it "round-trips a trait's parameters, associated types and supertraits" do
    declaration = type_declaration("Enumerable", "generic trait",
      type_parameters: ["K"],
      assoc_types: ["Elem"],
      supertraits: ["Std::Traits::Cmp"],
      methods: [signature("each", return_type: "Nil",
        block_parameter: "& : (Elem -> Nil)", required: true)])

    with_temporary_file do |path|
      Iyi::IyiMod.write sample_artifact(types: [declaration]), path
      read = Iyi::IyiMod.read(path).exports.types[0]

      read.type_parameters.should eq ["K"]
      read.assoc_types.should eq ["Elem"]
      read.supertraits.should eq ["Std::Traits::Cmp"]
    end
  end

  it "dumps a trait and an impl as they were declared" do
    io = IO::Memory.new
    Iyi::IyiMod.dump sample_artifact(
      types: [type_declaration("Enumerable", "generic trait",
        assoc_types: ["Elem"],
        supertraits: ["Cmp"],
        methods: [signature("each", return_type: "Nil", required: true)])],
      impls: [impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"],
        free_variable_bounds: [{"T", "Cmp"}],
        assoc_types: [{"Elem", "T"}])],
    ), io
    text = io.to_s

    # `generic` is how a type describes itself, not how anyone declares one.
    text.should contain "  pub trait Enumerable : Cmp"
    text.should contain "    type Elem"
    text.should contain "  impl ::Std::Enumerable::Enumerable for ::Std::List::List(T) forall T : Cmp"
    text.should contain "    type Elem = T"
  end

  # What `import` compiles against instead of the module's source (R-1). It is
  # iyi rather than a second grammar, so the parser that read the module reads
  # its declarations back.
  it "renders the declarations a consumer compiles against" do
    io = IO::Memory.new
    Iyi::IyiMod.declarations sample_artifact(
      exports: [signature("polite", ["name : String"], "String")],
      types: [type_declaration("Greet", "trait",
        methods: [signature("greet", return_type: "String", required: true)])],
      impls: [impl_record("Greet", "User")],
    ), io
    text = io.to_s

    text.should contain "module app/greeter"
    # A body is absent, not empty: a call is typed from the return annotation,
    # which is what makes this enough for the front end and nothing else.
    text.should contain "pub def polite(name : String) : String\nend\n"
    text.should contain "pub trait Greet\n  abstract def greet : String\nend\n"
    # An `abstract def` ends at its signature and takes no `end` of its own.
    text.should_not contain "abstract def greet : String\n  end"
    text.should contain "impl ::Greet for ::User\nend\n"
    # The impl comes after the type it targets, because the requirement check
    # reads the methods off the target rather than out of the impl's body.
    text.index("pub trait Greet").not_nil!.should be < text.index("impl ::Greet for ::User").not_nil!
  end

  it "renders a generic type and the impl that answers its associated type" do
    io = IO::Memory.new
    Iyi::IyiMod.declarations sample_artifact(
      types: [type_declaration("List", "generic struct", type_parameters: ["T"],
        methods: [signature("each", return_type: "Nil", block_parameter: "& : (T -> Nil)")])],
      impls: [impl_record("Std::Enumerable::Enumerable", "Std::List::List(T)",
        free_variables: ["T"], assoc_types: [{"Elem", "T"}])],
    ), io
    text = io.to_s

    text.should contain "pub struct List(T)"
    text.should contain "  def each(& : (T -> Nil)) : Nil\n  end\n"
    text.should contain "impl ::Std::Enumerable::Enumerable for ::Std::List::List(T) forall T\n  type Elem = T\nend\n"
  end

  # A `--release` consumer is one LLVM module, and one module gives every
  # symbol the program defines internal linkage. The artifact's object code
  # names some of them from outside: `a + b` checks overflow through
  # `__iyi_raise_overflow`, and `Tally.new` allocates through the collector's
  # globals and reads a type id. `Half.of` above names none, which is why it
  # linked.
  it "links a release consumer against object code that checks overflow and allocates" do
    with_tempdir("iyimod_release_closure") do
      modules = {"app/sum.iyi" => <<-IYI}
        module app/sum

        pub class Tally
          getter n : Int32

          def initialize(@n : Int32)
          end
        end

        pub def total(a : Int32, b : Int32) : Int32
          a + b
        end

        pub def tally(n : Int32) : Tally
          Tally.new(n * 2)
        end
        IYI
      main = <<-IYI
        module main

        import app/sum::*

        puts total(40, 2)
        puts tally(21).n
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main, release: true)
      from_source.should eq "42\n42\n"
      from_artifact.should eq from_source
    end
  end

  # A union written wider than the body answers. The producer keyed its symbol
  # on what the body inferred, `mixed<Bool>:(Int32 | String)`, and a consumer
  # reading the declaration asked for `| Nil` on the end.
  it "links a def whose body answers fewer union members than it declares" do
    with_tempdir("iyimod_narrow_union") do
      modules = {"app/mixed.iyi" => <<-IYI}
        module app/mixed

        pub def mixed(flag : Bool) : Int32 | String | Nil
          flag ? 4 : "four"
        end

        pub def maybe(n : Int32) : Int32?
          n
        end

        pub def either(flag : Bool) : Int32 | String
          flag ? 1 : "one"
        end
        IYI
      main = <<-IYI
        module main

        import app/mixed::*

        puts mixed(true).inspect
        puts mixed(false).inspect
        puts maybe(3).inspect
        puts either(false)
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "4\n\"four\"\n3\none\n"
      from_artifact.should eq from_source
    end
  end

  # A body and an initialiser read back from an artifact are located where
  # they were written, not in the artifact (issue #140). A macro that asks
  # `@caller` where it was called from answered `mods/app/box.iyimod:13:3`
  # from the artifact, a line of the declarations it renders, and
  # `Eiy.render` read its template from beside the artifact; an error inside
  # the body pointed into the rendering too. Still read from the artifact for
  # what the build decides: a `defer` travels as the `ensure` it lowers to,
  # and located in an `.iyi` file that was refused as one written there.
  it "locates a travelling body and the initialiser in the module's source" do
    with_tempdir("iyimod_body_positions") do
      modules = {"app/box.iyi" => <<-IYI}
        module app/box

        pub macro written_at
          {{ "\#{@caller.first.filename.id}:\#{@caller.first.line_number}:\#{@caller.first.column_number}" }}
        end

        pub def where(x : T) : String forall T
          written_at
        end

        pub def sized(x : T) : Int32 forall T
          x.size +    1
        end

        Placed = written_at

        pub def placed : String
          Placed
        end

        pub def guarded(x : T) : Int32 forall T
          defer puts "left"
          x.size
        end
        IYI
      main = <<-IYI
        module main

        import app/box::{where, sized, placed, guarded}

        puts where(1)
        puts placed
        puts sized("ab")
        puts guarded("ab")
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      box = File.expand_path("app/box.iyi")
      from_source.should eq "#{box}:8:3\n#{box}:15:10\n3\nleft\n2\n"
      from_artifact.should eq from_source

      File.write "unsized.iyi", "module main\n\nimport app/box::{sized}\n\nputs sized(2)\n"
      unsized = Iyi::Compiler::Source.new(File.expand_path("unsized.iyi"), File.read("unsized.iyi"))
      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"
      consumer.no_codegen = true
      error = expect_raises(Iyi::TypeException, /undefined method 'size' for Int32/) do
        consumer.compile unsized, "unused"
      end
      error.to_s.should contain "#{Path["app", "box.iyi"]}:12:5"
      error.to_s.should_not contain ".iyimod:"
    end
  end

  # A parameter written as a trait. No value has a trait as its type, so the
  # producer instantiated `area_of` per argument - including the consumer's
  # own `Main::Tri` - and a consumer reading the declaration asked for
  # `area_of<App::Shapes::Shape>`, which nobody emitted.
  it "links a def whose parameter is written as a trait" do
    with_tempdir("iyimod_trait_parameter") do
      modules = {"app/shapes.iyi" => <<-IYI}
        module app/shapes

        pub trait Shape
          abstract def area : Int32
        end

        pub struct Sq
          getter side : Int32

          def initialize(@side : Int32)
          end
        end

        impl Shape for Sq
          def area : Int32
            side * side
          end
        end

        pub def area_of(x : Shape) : Int32
          x.area + 1
        end
        IYI
      main = <<-IYI
        module main

        import app/shapes::*

        struct Tri
          getter b : Int32

          def initialize(@b : Int32)
          end
        end

        impl Shape for Tri
          def area : Int32
            b * 3
          end
        end

        puts area_of(Sq.new(3))
        puts area_of(Tri.new(4))
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "10\n13\n"
      from_artifact.should eq from_source
    end
  end

  # Two parameters the producer compiled narrower than written: a class
  # parameter called with the consumer's own subclass, and a private def's
  # union reached from a travelling body with one member. Each was declared
  # as written with no symbol behind it.
  it "links a def whose parameter is a class or a private union" do
    with_tempdir("iyimod_narrow_instantiation") do
      modules = {"lib/u.iyi" => <<-IYI}
        module lib/u

        pub abstract class Base
          def initialize
          end
        end

        pub def name_of(klass : Base.class) : String
          klass.to_s
        end

        pub def open(uri : Int32 | String) : String
          build(uri)
        end

        def build(uri : Int32 | String) : String
          "built \#{uri}"
        end
        IYI
      main = <<-IYI
        module main

        import lib/u::*

        class Sub < Base
        end

        puts name_of(Sub)
        puts open("x")
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "Main::Sub\nbuilt x\n"
      from_artifact.should eq from_source
    end
  end

  # A class variable on a base class is copied onto each subclass. The base
  # module's artifact declared the copy on `Sub`, a type of another module,
  # and that reopening declared `Sub` under `Reference` before `lib/sub`'s
  # own artifact was read.
  it "leaves a subclass in another module to that module's artifact" do
    with_tempdir("iyimod_inherited_class_var") do
      modules = {"lib/base.iyi" => <<-BASE, "lib/sub.iyi" => <<-SUB}
        module lib/base

        pub abstract class Base
          @@count = 0

          def self.bump : Int32
            @@count += 1
          end

          def initialize
          end

          def count : Int32
            @@count
          end
        end
        BASE
        module lib/sub

        import lib/base::*

        pub class Sub < Base
        end
        SUB
      main = <<-IYI
        module main

        import lib/base::*
        import lib/sub::*

        Base.bump
        Sub.bump
        Sub.bump
        puts Sub.new.count
        puts Base.bump
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "2\n2\n"
      from_artifact.should eq from_source
    end
  end

  # A generic body with macro code travels as text and is expanded by the
  # consumer, under the artifact's path. That path is no `.iyi`, so the
  # expansion was lexed as the other language's and `raw!` was a method name.
  it "reads a propagation in a travelled body's macro code" do
    with_tempdir("iyimod_macro_propagate") do
      modules = {"lib/r.iyi" => <<-IYI}
        module lib/r

        pub class Fail
          def initialize
          end
        end

        impl Error for Fail
          def message : String
            "fail"
          end
        end

        pub class Reader
          def initialize
          end

          def raw : Int32 | Fail
            7
          end

          def get(klass : T.class) : T | Fail forall T
            {% if T == Int32 %}
              value = raw!
              value
            {% else %}
              Fail.new
            {% end %}
          end
        end
        IYI
      main = <<-IYI
        module main

        import lib/r::*

        puts Reader.new.get(Int32).or_panic
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "7\n"
      from_artifact.should eq from_source
    end
  end

  # `@items = [] of String` in a type body runs in `initialize`, the way the
  # typed `@items : Array(String) = [] of String` does, and travels the same
  # way. Read as a statement it refused every consumer: "has code inside a
  # type body that has to run".
  it "carries an instance variable's initialiser written without a type" do
    with_tempdir("iyimod_untyped_ivar") do
      modules = {"app/bag.iyi" => <<-IYI}
        module app/bag

        pub class Bag
          @items = [] of String

          def initialize
          end

          def add(item : String) : Int32
            @items << item
            @items.size
          end
        end

        pub class Stack(T)
          @items = [] of T

          def initialize(first : T)
            @items << first
          end

          def size : Int32
            @items.size
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/bag::*

        bag = Bag.new
        bag.add("a")
        puts bag.add("b")
        puts Stack.new(1).size
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "2\n1\n"
      from_artifact.should eq from_source
    end
  end

  # A generic type's empty `initialize` travels as an empty body, and an empty
  # body read back is a `Nop` - which is how a header looks. So the consumer
  # declared `Stack(Int32)#initialize` and never defined it.
  it "defines a generic type's empty method" do
    with_tempdir("iyimod_empty_generic_body") do
      modules = {"app/stack.iyi" => <<-IYI}
        module app/stack

        pub class Stack(T)
          @items : Array(T) = [] of T

          def initialize
          end

          def push(item : T) : Int32
            @items << item
            @items.size
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/stack::*

        puts Stack(Int32).new.push(5)
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "1\n"
      from_artifact.should eq from_source
    end
  end

  # The producer lays out Holder's trait field with a definition witness.
  # A consumer recompiling its generic forwarding body must restore that
  # witness too; a smaller trait representation reads the stored value with
  # the wrong ABI and can segfault.
  it "preserves a trait field layout when a consumer recompiles a generic forwarding body" do
    with_tempdir("iyimod_witness_field") do
      modules = {"app/values.iyi" => <<-IYI, "app/holder.iyi" => <<-IYI}
        module app/values

        pub trait Value
          abstract def value : Int32
        end

        pub class Number
          getter value : Int32

          def initialize(@value : Int32)
          end
        end

        impl Value for Number
        end

        # A fully declared trait parameter creates the producer-only witness.
        pub def check_value(value : Value) : Int32
          value.value
        end
        IYI
        module app/holder

        import app/values::{Value}

        pub def forward(value : Value, &block : Int32 -> T) : T forall T
          block.call(value.value)
        end

        pub class Holder
          @value : Value

          def initialize(@value : Value)
          end

          def apply(&block : Int32 -> T) : T forall T
            forward(@value) { |value| block.call(value) }
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/values::{Number}
        import app/holder::{Holder}

        puts Holder.new(Number.new(40)).apply { |value| value + 2 }
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "42\n"
      from_artifact.should eq from_source
    end
  end

  # Definition-site typing gave `Named` a witness type in the producing build,
  # so `names`'s dispatch over `Named` tests for it and the object code
  # numbers it. The consumer has no witness - nothing in its own source is
  # typed against `Named` - and refused the import over a type no value can
  # have.
  it "links object code that dispatches over a trait with a definition-typing witness" do
    with_tempdir("iyimod_witness") do
      modules = {"app/names.iyi" => <<-IYI}
        module app/names

        pub trait Named
          abstract def name : String
        end

        pub class Registry
          @all : Array(Named) = [] of Named

          def initialize
          end

          def add(item : Named) : Int32
            @all << item
            @all.size
          end

          def names : String
            @all.map(&.name).join(",")
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/names::*

        struct Own
          def initialize
          end
        end

        impl Named for Own
          def name : String
            "own"
          end
        end

        registry = Registry.new
        registry.add(Own.new)
        puts registry.names
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "own\n"
      from_artifact.should eq from_source
    end
  end

  # A trait's default method runs on the implementing type, which may be
  # another module's. Its unqualified names were looked up from that type,
  # so `lib/core`'s `twice` called the consumer's own `helper` - 7 where its
  # own module's says 106 - and, with no `helper` in the consumer, was
  # refused. `run`'s definition-typing witness took the same wrong turn.
  it "resolves a default method's functions in the trait's module" do
    with_tempdir("iyimod_default_scope") do
      modules = {"lib/core.iyi" => <<-IYI}
        module lib/core

        def helper(x : Int32) : Int32
          x + 100
        end

        pub trait Op
          abstract def apply(x : Int32) : Int32

          def twice(x : Int32) : Int32
            helper(apply(x))
          end
        end
        IYI
      main = <<-IYI
        module main

        import lib/core::*

        def helper(x : Int32) : Int32
          x + 1
        end

        struct A
          def initialize
          end
        end

        impl Op for A
          def apply(x : Int32) : Int32
            x * 2
          end
        end

        def run(o : Op) : Int32
          o.twice(3)
        end

        puts A.new.twice(3)
        puts run(A.new)
        puts helper(3)
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "106\n106\n4\n"
      from_artifact.should eq from_source
    end
  end

  # `.or` lowers to a temporary and an `if`, and a body that travels is the
  # normalized text: inside `#{}` that was two expressions where the parser
  # reads one, and the consumer stopped on "Unterminated string
  # interpolation" in a module that had compiled.
  it "carries a recovery inside an interpolation in a body that travels" do
    with_tempdir("iyimod_interpolated_or") do
      modules = {"lib/core.iyi" => <<-IYI}
        module lib/core

        pub struct Bad
          def initialize
          end
        end

        impl Error for Bad
          def message : String
            "bad"
          end
        end

        pub def half(x : Int32) : Int32 | Bad
          return Bad.new if x.odd?
          x // 2
        end

        pub def show(v : T, x : Int32) : String forall T
          "\#{v}: \#{half(x).or(-1)}"
        end
        IYI
      main = <<-IYI
        module main

        import lib/core::*

        puts show("a", 8)
        puts show(1, 3)
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "a: 4\n1: -1\n"
      from_artifact.should eq from_source
    end
  end

  # A signature with an error member is the def's type (III.1.8), and a
  # default method's body travels for its implementers. Read from the
  # artifact, where its location is no `.iyi`, the body's own answer typed
  # it: `Int32`, and `.or` on it was refused as having nothing to recover.
  it "keeps a travelled body's declared error union" do
    with_tempdir("iyimod_declared_union") do
      modules = {"lib/core.iyi" => <<-IYI}
        module lib/core

        pub struct Bad
          def initialize
          end
        end

        impl Error for Bad
          def message : String
            "bad"
          end
        end

        pub trait Op
          abstract def apply(x : Int32) : Int32 | Bad

          def twice(x : Int32) : Int32 | Bad
            apply(x).or(0) + 1
          end
        end

        pub struct Half
          def initialize
          end
        end

        impl Op for Half
          def apply(x : Int32) : Int32 | Bad
            return Bad.new if x.odd?
            x // 2
          end
        end
        IYI
      main = <<-IYI
        module main

        import lib/core::*

        def run(o : Op, x : Int32) : Int32
          o.twice(x).or(-1)
        end

        puts run(Half.new, 8)
        puts run(Half.new, 3)
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "5\n1\n"
      from_artifact.should eq from_source
    end
  end

  # An abstract generic class. Its kind is `abstract generic class`, and the
  # header took `generic ` off the front only, so the consumer read
  # `pub abstract generic class Src(T)` and stopped on "`pub abstract` takes a
  # class, a struct or a def".
  it "renders an abstract generic class it can read back" do
    with_tempdir("iyimod_abstract_generic") do
      modules = {"app/src.iyi" => <<-IYI}
        module app/src

        pub abstract class Src(T)
          abstract def value : T

          def pair : Array(T)
            [value, value]
          end
        end

        pub class IntSrc < Src(Int32)
          def initialize(@n : Int32)
          end

          def value : Int32
            @n * 2
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/src::*

        class StrSrc < Src(String)
          def value : String
            "s"
          end
        end

        puts IntSrc.new(4).pair
        puts StrSrc.new.pair
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "[8, 8]\n[\"s\", \"s\"]\n"
      from_artifact.should eq from_source
    end
  end

  # The producer's is_a? uses a union match containing a definition witness.
  # Execute both real-member and non-member branches from source-free code.
  it "round-trips object code matching a trait union containing a witness" do
    with_tempdir("iyimod_witness_union_round_trip") do
      modules = {"app/values.iyi" => <<-IYI}
        module app/values

        pub trait Value
          abstract def value : Int32
        end

        pub struct Number
          getter value : Int32

          def initialize(@value : Int32)
          end
        end

        impl Value for Number
        end

        # A direct trait restriction ensures definition typing builds a witness.
        pub def check_value(item : Value) : Int32
          item.value
        end

        pub class Reader
          @item : Value | Bool

          def initialize(@item : Value | Bool)
          end

          def read : Int32
            item = @item
            if item.is_a?(Value)
              item.value
            else
              -1
            end
          end
        end
        IYI
      main = <<-IYI
        module main

        import app/values::{Number, Reader}

        puts Reader.new(Number.new(42)).read
        puts Reader.new(false).read
        IYI
      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "42\n-1\n"
      from_artifact.should eq from_source
      artifact = Iyi::IyiMod.read(File.join("mods", "app", "values.iyimod"))
      artifact.match_types.select(&.includes?(" | ")).join("\n")
        .should contain(Iyi::DefinitionTyping::WITNESS_PREFIX)
    end
  end

  # Carried matches may embed witnesses in unions or generic arguments.
  # Restore those members without accepting missing ordinary types.
  it "restores witnesses needed by union matches before resolving carried references" do
    with_tempdir("iyimod_witness_match_refs") do
      text = <<-IYI
        module app/witness

        pub trait Value
          abstract def value : Int32
        end

        pub class Number
          def value : Int32
            40
          end
        end

        impl Value for Number
        end

        pub class Box(T)
        end
        IYI
      File.write "main.iyi", text
      witness = "IyiDefTypeWitness_App_Witness_Value"
      names = ["(App::Witness::Number | #{witness})", "App::Witness::Box(#{witness})"]
      program = Iyi::Program.new
      program.filename = File.expand_path("main.iyi")
      parser = program.new_parser(text)
      parser.filename = program.filename
      node = program.normalize(parser.parse)
      names.each do |name|
        program.iyi_artifact_refs << Iyi::Program::IyiArtifactRef.new("app/carried", name, node, true)
      end
      program.semantic node
      names.each { |name| program.iyi_artifact_match_types.has_key?(name).should be_true }
      program.types.has_key?(witness).should be_true
      program.iyi_artifact_refs.should be_empty

      # The witness may be restored, but a missing real union member must
      # still be refused; the compound type is not an unmatchable phantom.
      rejecting = Iyi::Program.new
      rejecting.filename = File.expand_path("main.iyi")
      reject_parser = rejecting.new_parser(text)
      reject_parser.filename = rejecting.filename
      reject_node = rejecting.normalize(reject_parser.parse)
      name = "(#{witness} | MissingRealType)"
      rejecting.iyi_artifact_refs << Iyi::Program::IyiArtifactRef.new("app/carried", name, reject_node, true)
      expect_raises(Iyi::CodeError, /MissingRealType/) do
        rejecting.semantic reject_node
      end
    end
  end
end

# iyi: the ecosystem and R-1, together (SPEC.md Part V item 12d).
#
# `--crystal` gives a program Crystal's library; a `.iyimod` gives a consumer a
# module it does not compile. Each was useful alone and refused together, and
# what the refusal protected against turned out to be three concrete things
# rather than one general one: the main module's helpers do not travel, the
# consumer's numbering is its own, and a module's requires are not the
# consumer's. All three have answers, so the combination is now supported and
# these are what keeps it working.
describe "a module compiled against Crystal's library" do
  it "calls a captured closure from a source-absent Crystal-library artifact" do
    with_tempdir("iyimod_crystal_library_closure") do
      Dir.mkdir_p "app"
      File.write "app/closure.iyi", <<-IYI
        module app/closure

        @[NoInline]
        pub def make(offset : Int32) : Proc(Int32, Int32)
          ->(n : Int32) { n + offset }
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/closure

        @[NoInline]
        def invoke(action : Proc(Int32, Int32), value : Int32) : Int32
          action.call(value)
        end

        target = App::Closure.make(1)
        action = ->(n : Int32) { target.call(n) * 2 }
        puts invoke(action, 20)
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))
      producer = create_spec_compiler
      producer.release!
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq("42")

      path = File.join("mods", "app", "closure.iyimod")
      artifact = Iyi::IyiMod.read(path, want_object_code: true)
      artifact.crystal_library.should be_true
      artifact.object_code.should_not be_empty
      Dir.mkdir_p "rewritten/app"
      rewritten_path = File.join("rewritten", "app", "closure.iyimod")
      Iyi::IyiMod.write artifact, rewritten_path
      rewritten = Iyi::IyiMod.read(rewritten_path, want_object_code: true)
      rewritten.object_code.should eq(artifact.object_code)

      File.delete "app/closure.iyi"
      File.exists?("app/closure.iyi").should be_false
      consumer = create_spec_compiler
      consumer.release!
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq("42")

      File.delete path
      File.exists?(path).should be_false
      rewritten_consumer = create_spec_compiler
      rewritten_consumer.release!
      rewritten_consumer.use_iyimod = "rewritten"
      rewritten_consumer.compile source, File.expand_path("from-rewritten-artifact")
      `./from-rewritten-artifact`.chomp.should eq("42")
    end
  end

  it "travels through a .iyimod and links, replaying its requires" do
    with_tempdir("iyimod_crystal_library") do
      Dir.mkdir_p "app"
      # `uri` and not only `json`, because the requires are the point: the
      # consumer requires neither, and `URI::Error.class:type_id` was the
      # symbol that went undefined when they did not travel.
      File.write "app/store.iyi", <<-IYI
        module app/store

        require "json"
        require "uri"

        pub def encode(name : String) : String
          {"name" => name}.to_json
        end

        pub def slug(name : String) : String
          URI.encode_path_segment(name)
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/store::*

        puts encode("iyi")
        puts slug("a b")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq %({"name":"iyi"}\na%20b)

      artifact = Iyi::IyiMod.read(File.join("mods", "app", "store.iyimod"))
      artifact.crystal_library.should be_true
      artifact.requires.should eq ["json", "uri"]

      File.delete "app/store.iyi"

      consumer = create_spec_compiler
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq %({"name":"iyi"}\na%20b)
    end
  end

  # The thing a shared library has to be shared: one copy of its state. Both
  # sides were compiled by the same compiler and mangle the same names, so the
  # linker folds them — but "the link succeeded" would also be true of a
  # program with two copies of a lazily initialised constant, and that program
  # is wrong in a way nothing reports.
  it "shares the library's state with the program that consumes it" do
    with_tempdir("iyimod_crystal_state") do
      Dir.mkdir_p "app"
      File.write "app/ids.iyi", <<-IYI
        module app/ids

        require "json"

        pub def stdout_id : UInt64
          STDOUT.object_id
        end

        pub def program_name_id : UInt64
          PROGRAM_NAME.object_id
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/ids::*

        puts stdout_id == STDOUT.object_id
        puts program_name_id == PROGRAM_NAME.object_id
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")

      File.delete "app/ids.iyi"

      consumer = create_spec_compiler
      consumer.use_iyimod = "mods"
      consumer.compile source, File.expand_path("from-artifact")
      `./from-artifact`.chomp.should eq "true\ntrue"
    end
  end

  it "refuses to be imported by a program built against iyi's prelude" do
    with_tempdir("iyimod_crystal_into_iyi") do
      Dir.mkdir_p "app"
      File.write "app/store.iyi", <<-IYI
        module app/store

        require "json"

        pub def encode(name : String) : String
          {"name" => name}.to_json
        end
        IYI
      File.write "producer.iyi", <<-IYI
        module main

        import app/store::*

        puts encode("iyi")
        IYI

      producer = create_spec_compiler
      producer.emit_iyimod = "mods"
      producer.compile Iyi::Compiler::Source.new(
        File.expand_path("producer.iyi"), File.read("producer.iyi")),
        File.expand_path("producer")

      File.write "consumer.iyi", <<-IYI
        module main

        import app/store::*

        puts 1
        IYI

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.use_iyimod = "mods"

      expect_raises Iyi::CodeError, /built against Crystal's standard library/ do
        consumer.compile Iyi::Compiler::Source.new(
          File.expand_path("consumer.iyi"), File.read("consumer.iyi")),
          File.expand_path("consumer")
      end
    end
  end

  it "refuses to import a module built against iyi's prelude" do
    with_tempdir("iyimod_iyi_into_crystal") do
      Dir.mkdir_p "app"
      File.write "app/greet.iyi", <<-IYI
        module app/greet

        pub def hello(name : String) : String
          "merhaba " + name
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/greet::*

        puts hello("iyi")
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("producer")

      consumer = create_spec_compiler
      consumer.use_iyimod = "mods"

      expect_raises Iyi::CodeError, /built against iyi's prelude/ do
        consumer.compile source, File.expand_path("consumer")
      end
    end
  end

  # A generic method's body travels as source printed after the normalizer
  # has expanded it, and `.or_panic` expands to an assignment and an `if` in
  # one `Expressions`. Printed bare inside `twice(...)` the consumer read
  # `twice(__temp = parse(text)` and stopped at "expecting token ')', not
  # 'if'". The `!` beside it expands the same way, inside an array literal.
  it "carries a body whose argument expanded to statements" do
    with_tempdir("iyimod_expanded_argument") do
      modules = {
        "orp.iyi" => <<-IYI,
          module orp

          pub struct OrpError
            getter text : String

            def initialize(@text : String)
            end
          end

          impl Error for OrpError
            def message : String
              @text
            end
          end

          pub struct Orp
            def self.parse(text : String) : Int32 | OrpError
              text.empty? ? OrpError.new("empty") : text.size
            end

            def self.twice(value : Int32, type : T.class) : Int32 forall T
              value * 2
            end

            def self.read(text : String, type : T.class) : Int32 forall T
              twice(parse(text).or_panic, type)
            end

            def self.both(text : String, type : T.class) : Array(Int32) | OrpError forall T
              [parse(text)!, twice(value: parse(text).or_panic, type: type)]
            end
          end
          IYI
      }
      main = <<-IYI
        module main

        import orp::{Orp}

        puts Orp.read("abc", Int32)
        puts Orp.both("ab", Int32)
        IYI

      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "6\n[2, 4]\n"
      from_artifact.should eq from_source
    end
  end

  # Adding an overload orders it against the ones already there, and that
  # resolves an alias one of them is restricted to on the spot. `std/toml`'s
  # `Any` held `alias Type = ... | TOMLDateTime | ...` beside two
  # `initialize`s, below `TOMLDateTime` in the source; the artifact declares
  # types by name, so `Any` came first and the consumer said "undefined
  # constant TOMLDateTime". The types an alias names are now declared before
  # the type holding it, whether the alias names them bare or qualified.
  it "declares the types an alias names before the alias" do
    with_tempdir("iyimod_alias_order") do
      modules = {
        "al.iyi" => <<-IYI,
          module al

          pub struct Zed
            getter n : Int32

            def initialize(@n : Int32)
            end
          end

          pub struct Any
            alias Type = Int32 | Zed | Array(Any)

            getter raw : Type

            def initialize(@raw : Type)
            end

            def initialize(value : String)
              @raw = value.size
            end

            def zed? : Bool
              @raw.is_a?(Zed)
            end
          end

          pub struct Box
            alias Held = String | ::Al::Zed

            getter held : Held

            def initialize(@held : Held)
            end

            def initialize(value : Int32)
              @held = value.to_s
            end
          end
          IYI
      }
      main = <<-IYI
        module main

        import al::{Any, Box, Zed}

        puts Any.new(Zed.new(3)).zed?
        puts Any.new("abc").raw
        puts Box.new(4).held
        puts Box.new(Zed.new(5)).held.is_a?(Zed)
        IYI

      from_source, from_artifact = iyimod_round_trip(modules, main)
      from_source.should eq "true\n3\n4\ntrue\n"
      from_artifact.should eq from_source
    end
  end

  it "observed producer and consumer inline effect bodies with no __iyi_effect_ artifact symbols" do
    with_tempdir("iyimod_observed_effect_inline") do
      modules = {
        "helpers.iyi" => <<-IYI,
          module helpers

          import std/dir::{Dir}
          import std/env::{ENV}

          pub def probe_effects : Int32
            ENV["X"] = "1"
            Dir.children(".").size >= 0 ? 42 : 0
          end
          IYI
      }
      main = <<-IYI
        module main

        import helpers::{probe_effects}

        puts probe_effects
        IYI

      modules.each do |path, text|
        Dir.mkdir_p File.dirname(path)
        File.write path, text
      end
      File.write "main.iyi", main
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), main)

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.flags << "iyi_observe"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      from_source = `./from-source`

      modules.each_key { |path| File.delete path }

      consumer = create_spec_compiler
      consumer.prelude = "iyi/prelude"
      consumer.flags << "iyi_observe"
      consumer.use_iyimod = "mods"
      result = consumer.compile source, File.expand_path("from-artifact")
      from_artifact = `./from-artifact`

      result.program.iyi_artifact_symbols.none?(&.includes?("__iyi_effect_")).should be_true
      from_source.should eq "42\n"
      from_artifact.should eq from_source
    end
  end

  it "observed warm consumer resolves artifact type ids while unimported def return type is refused" do
    with_tempdir("iyimod_warm_std_time") do
      modules = {
        "app.iyi" => <<-IYI,
          module app

          import std/dir::{Dir}

          pub def count_entries : Int32
            Dir.children(".").size >= 0 ? 1 : 0
          end
          IYI
      }
      main = <<-IYI
        module main

        import app::{count_entries}

        puts count_entries
        IYI

      modules.each do |path, text|
        Dir.mkdir_p File.dirname(path)
        File.write path, text
      end
      File.write "main.iyi", main
      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), main)

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.flags << "iyi_observe"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      from_source = `./from-source`

      time_art = Iyi::IyiMod.read(File.join("mods", "std", "time.iyimod"))
      time_art.type_ids.any?(&.includes?("Std::Time::")).should be_true

      modules.each_key { |path| File.delete path }

      old_warm = ENV["IYI_WARM"]?
      ENV["IYI_WARM"] = "1"
      begin
        Iyi::Compiler.preanalysed.clear
        consumer = create_spec_compiler
        consumer.prelude = "iyi/prelude"
        consumer.flags << "iyi_observe"
        consumer.use_iyimod = "mods"
        consumer.compile source, File.expand_path("from-artifact")
        from_artifact = `./from-artifact`
        from_artifact.should eq from_source

        File.write "unimported.iyi", <<-IYI
          module main

          def peek : Std::Time::Location::Zone?
            nil
          end
          IYI
        unimported = Iyi::Compiler::Source.new(File.expand_path("unimported.iyi"), File.read("unimported.iyi"))
        refuser = create_spec_compiler
        refuser.prelude = "iyi/prelude"
        refuser.flags << "iyi_observe"
        refuser.use_iyimod = "mods"
        refuser.no_codegen = true
        expect_raises(Iyi::TypeException, /`Std::Time` is not imported here/) do
          refuser.compile unimported, "unused"
        end
      ensure
        Iyi::Compiler.preanalysed.clear
        if old_warm
          ENV["IYI_WARM"] = old_warm
        else
          ENV.delete("IYI_WARM")
        end
      end
    end
  end

  it "carries a type its module does not export under observed warm build" do
    with_tempdir("iyimod_type_ids_private_warm") do
      Dir.mkdir_p "app"
      File.write "app/box.iyi", <<-IYI
        module app/box

        struct Secret
          @n : Int32

          def initialize(@n : Int32)
          end

          def n : Int32
            @n
          end
        end

        pub def total : Int32
          items = Array(Secret).new
          items << Secret.new(2)
          items << Secret.new(3)
          items[0].n + items[1].n
        end
        IYI
      File.write "main.iyi", <<-IYI
        module main

        import app/box

        puts App::Box.total
        IYI

      source = Iyi::Compiler::Source.new(File.expand_path("main.iyi"), File.read("main.iyi"))

      producer = create_spec_compiler
      producer.prelude = "iyi/prelude"
      producer.flags << "iyi_observe"
      producer.emit_iyimod = "mods"
      producer.compile source, File.expand_path("from-source")
      `./from-source`.chomp.should eq "5"

      File.delete "app/box.iyi"

      old_warm = ENV["IYI_WARM"]?
      ENV["IYI_WARM"] = "1"
      begin
        Iyi::Compiler.preanalysed.clear
        consumer = create_spec_compiler
        consumer.prelude = "iyi/prelude"
        consumer.flags << "iyi_observe"
        consumer.use_iyimod = "mods"
        consumer.compile source, File.expand_path("from-artifact")
        `./from-artifact`.chomp.should eq "5"

        File.write "reach.iyi", <<-IYI
          module main

          import app/box

          puts App::Box::Secret.new(1).n
          IYI
        reaching = Iyi::Compiler::Source.new(File.expand_path("reach.iyi"), File.read("reach.iyi"))

        refuser = create_spec_compiler
        refuser.prelude = "iyi/prelude"
        refuser.flags << "iyi_observe"
        refuser.use_iyimod = "mods"
        refuser.no_codegen = true
        expect_raises(Iyi::TypeException, /does not export App::Box::Secret/) do
          refuser.compile reaching, "unused"
        end
      ensure
        Iyi::Compiler.preanalysed.clear
        if old_warm
          ENV["IYI_WARM"] = old_warm
        else
          ENV.delete("IYI_WARM")
        end
      end
    end
  end

  it "resolves composite generic, tuple, union, proc and metaclass artifact type references" do
    with_tempdir("iyimod_composite_refs") do
      compiler = create_spec_compiler
      compiler.prelude = "iyi/prelude"
      compiler.no_codegen = true
      source = Iyi::Compiler::Source.new("test.iyi", <<-IYI
        module spec/test

        import std/time::{Time}

        puts Time.utc(2026, 1, 1, 0, 0, 0)
        IYI
      )
      result = compiler.compile(source, "unused")
      program = result.program
      program.filename = ""

      dummy_decl = Iyi::ImportDecl.new(["std", "time"])

      z_type = "Std::Time::Location::Zone"
      l_type = "Std::Time::Location"

      type_id_names = [
        "Array(#{z_type})",
        "NamedTuple(zone: #{z_type})",
        "(#{z_type} | Nil)",
        "Proc(#{z_type}, Nil)",
        "#{l_type}.class",
      ]

      match_names = [
        z_type,
        "Array(#{z_type})",
      ]

      type_id_names.each do |tname|
        program.iyi_artifact_refs << Iyi::Program::IyiArtifactRef.new("std/time", tname, dummy_decl, match: false)
      end

      match_names.each do |mname|
        program.iyi_artifact_refs << Iyi::Program::IyiArtifactRef.new("std/time", mname, dummy_decl, match: true)
      end

      program.resolve_iyi_artifact_refs

      numbered_names = program.iyi_artifact_numbered_types.map(&.to_s)
      type_id_names.each do |expected_name|
        numbered_names.should contain(expected_name)
      end
      match_names.each do |mname|
        program.iyi_artifact_match_types.has_key?(mname).should be_true
      end
    end
  end
end
