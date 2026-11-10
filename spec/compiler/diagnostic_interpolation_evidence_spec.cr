require "../support/syntax"
require "base64"

# Parses under capture and returns the root with the accepted input that the
# verifiers bind to. The input is taken before parsing, as the parser requires.
private def capture_interpolation_root(source : String, iyi : Bool = false) : {Iyi::ASTNode, Iyi::AcceptedCaptureInput}
  parser = Iyi::Parser.new(source)
  parser.filename = "/spec/interpolation_evidence.cr"
  parser.diagnostic_source_file = "/spec/interpolation_evidence.cr"
  parser.iyi = iyi
  parser.diagnostic_capture = true
  input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
    nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
  root = parser.parse
  {root, input}
end

# The one literal a string constituent carries, checked against the source
# bytes it claims and the verifier that binds them.
private def assert_piece_evidence(node : Iyi::StringLiteral, source : String, input : Iyi::AcceptedCaptureInput,
                                  raw : String, decoded : String) : Iyi::DiagnosticParsedLiteral
  literal = node.diagnostic_literal_names[{"value", 0}]
  Base64.decode(literal.decoded_base64).should eq(decoded.to_slice)
  literal.input_sha256.should eq(input.input_sha256)
  literal.segments.size.should eq(1)
  segment = literal.segments.first
  source.byte_slice(segment.start_offset, segment.end_offset - segment.start_offset).should eq(raw)
  Base64.decode(segment.raw_base64).should eq(raw.to_slice)
  Iyi::DiagnosticLiteralInputChecks.verify_owner_field!(node, "value", 0, input)
  literal
end

# A method call's name is observed from its own token, not reconstructed.
private def assert_observed_name(node : Iyi::ASTNode, raw : String) : Nil
  slots = node.diagnostic_name_slots
  primary = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
  slots.has_key?(primary).should be_true
  value = slots[primary].first
  value.should be_a(Iyi::DiagnosticNameValue::Observed)
  token = value.as(Iyi::DiagnosticNameValue::Observed).source_token
  token.raw_text.should eq(raw)
  token.token_kind.should eq(raw)
end

describe "interpolated string constituents" do
  it "binds the constituent to its own token, not to the text it decodes to" do
    source = %q("#{a}: #{b}")
    root, input = capture_interpolation_root(source)
    interp = root.as(Iyi::StringInterpolation)
    piece = interp.expressions[1].as(Iyi::StringLiteral)
    piece.value.should eq(": ")
    piece.location.should_not be_nil
    literal = assert_piece_evidence(piece, source, input, ": ", ": ")
    production = piece.diagnostic_literal_productions[{"value", 0}].first
    production.production.should eq(Iyi::DiagnosticLiteralProduction::StringPiece)
    production.delimiter_kind.should eq("STRING")
    witness = production.witnesses.first
    witness.kind.should eq(Iyi::DiagnosticLiteralWitnessKind::StringPiece)
    witness.start_offset.should eq(literal.segments.first.start_offset)
    witness.end_offset.should eq(literal.segments.first.end_offset)
  end

  it "keeps an escape as its raw bytes and its decoded value" do
    source = %q("#{a}\n#{b}")
    root, input = capture_interpolation_root(source)
    piece = root.as(Iyi::StringInterpolation).expressions[1].as(Iyi::StringLiteral)
    piece.value.should eq("\n")
    assert_piece_evidence(piece, source, input, %q(\n), "\n")
  end

  it "keeps adjacent escapes as separate constituents with no gap between them" do
    source = %q("#{a}\n\t#{b}")
    root, input = capture_interpolation_root(source)
    expressions = root.as(Iyi::StringInterpolation).expressions
    first = expressions[1].as(Iyi::StringLiteral)
    second = expressions[2].as(Iyi::StringLiteral)
    first_literal = assert_piece_evidence(first, source, input, %q(\n), "\n")
    second_literal = assert_piece_evidence(second, source, input, %q(\t), "\t")
    first_literal.segments.first.end_offset.should eq(second_literal.segments.first.start_offset)
  end

  it "binds duplicate text to each of its own positions" do
    source = %q("#{a}x#{b}x")
    root, input = capture_interpolation_root(source)
    expressions = root.as(Iyi::StringInterpolation).expressions
    first_offset = source.byte_index("x").not_nil!
    second_offset = source.byte_index("x", first_offset + 1).not_nil!
    first = expressions[1].as(Iyi::StringLiteral)
    second = expressions[3].as(Iyi::StringLiteral)
    first_literal = assert_piece_evidence(first, source, input, "x", "x")
    second_literal = assert_piece_evidence(second, source, input, "x", "x")
    first_literal.segments.first.start_offset.should eq(first_offset)
    second_literal.segments.first.start_offset.should eq(second_offset)
  end

  it "binds a constituent after a byte order mark to the offsets of the original input" do
    source = "\uFEFF" + %q("#{a}: #{b}")
    root, input = capture_interpolation_root(source)
    piece = root.as(Iyi::StringInterpolation).expressions[1].as(Iyi::StringLiteral)
    assert_piece_evidence(piece, source, input, ": ", ": ")
  end

  it "gives a folded constant the evidence of the literal it was folded from" do
    source = %q("#{a}#{"b"}")
    root, input = capture_interpolation_root(source)
    piece = root.as(Iyi::StringInterpolation).expressions[1].as(Iyi::StringLiteral)
    piece.value.should eq("b")
    assert_piece_evidence(piece, source, input, %q("b"), "b")
  end

  it "keeps the lexical mode of the input it was captured under" do
    source = %q("#{a}: #{b}")
    root, input = capture_interpolation_root(source, iyi: true)
    piece = root.as(Iyi::StringInterpolation).expressions[1].as(Iyi::StringLiteral)
    literal = assert_piece_evidence(piece, source, input, ": ", ": ")
    literal.lexical_mode.should eq("Iyi")
    input.lexical_mode.should eq("Iyi")
  end

  it "refuses a constituent whose decoded value or witness is mutated" do
    source = %q("#{a}: #{b}")
    root, input = capture_interpolation_root(source)
    piece = root.as(Iyi::StringInterpolation).expressions[1].as(Iyi::StringLiteral)
    literal = piece.diagnostic_literal_names[{"value", 0}]
    production = piece.diagnostic_literal_productions[{"value", 0}].first

    expect_raises(ArgumentError, /decoded value mismatch/) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [production], "z", input)
    end

    witness = production.witnesses.first
    shorter = Iyi::DiagnosticLiteralWitness.new(witness.kind, witness.start_offset, witness.end_offset - 1)
    altered = Iyi::DiagnosticLiteralProductionSegment.new(production.production, production.start_offset,
      production.end_offset, production.raw_base64, production.delimiter_kind, production.nest,
      production.end_delimiter, production.allow_escapes, [shorter])
    expect_raises(ArgumentError) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [altered], ": ", input)
    end

    wrong_bytes = Iyi::DiagnosticLiteralProductionSegment.new(production.production, production.start_offset,
      production.end_offset, Base64.strict_encode("zz".to_slice), production.delimiter_kind, production.nest,
      production.end_delimiter, production.allow_escapes, production.witnesses)
    expect_raises(ArgumentError, /literal production input bytes mismatch/) do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [wrong_bytes], ": ", input)
    end
  end

  it "leaves a heredoc constituent unattested, so the strict check refuses it" do
    source = "x = <<-EOS\n  a\#{b}c\n  EOS\n"
    root, input = capture_interpolation_root(source)
    heredoc = root.as(Iyi::Assign).value.as(Iyi::StringInterpolation)
    strings = heredoc.expressions.select(Iyi::StringLiteral).map(&.as(Iyi::StringLiteral))
    strings.should_not be_empty
    strings.each { |node| node.diagnostic_literal_names_count.should be_nil }
    expect_raises(ArgumentError, /literal value lacks source or construction evidence/) do
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end

  it "leaves a regex constituent unattested" do
    source = %q(/a#{b}c/)
    root, _input = capture_interpolation_root(source)
    pattern = root.as(Iyi::RegexLiteral).value.as(Iyi::StringInterpolation)
    strings = pattern.expressions.select(Iyi::StringLiteral).map(&.as(Iyi::StringLiteral))
    strings.size.should eq(2)
    strings.each { |node| node.diagnostic_literal_names_count.should be_nil }
  end
end

describe "bracket and operator method names" do
  it "observes the empty bracket call name from its own token" do
    root, input = capture_interpolation_root("g[]")
    call = root.as(Iyi::Call)
    call.name.should eq("[]")
    assert_observed_name(call, "[]")
    Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
  end

  it "still refuses a bracket call with an argument, which has no evidence of its own" do
    root, input = capture_interpolation_root("g[0]")
    expect_raises(ArgumentError, /Call\.name/) do
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end

  it "observes an operator method called after a dot from its own token" do
    {"f.+(1)" => "+", "f.==(1)" => "==", "f.<=>(1)" => "<=>"}.each do |source, name|
      root, input = capture_interpolation_root(source)
      call = root.as(Iyi::Call)
      call.name.should eq(name)
      assert_observed_name(call, name)
      Iyi::DiagnosticRecordedEvidenceInputCheck.new(input).verify!(root)
    end
  end
end
