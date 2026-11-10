require "../support/syntax"
require "base64"

# These are structural checks only: their input is a claim, not an authority.
private def s3_input(source : String) : Iyi::AcceptedCaptureInput
  parser = Iyi::Parser.new(source)
  parser.filename = "/spec/s3-model.cr"
  parser.diagnostic_source_file = "/spec/s3-model.cr"
  parser.diagnostic_capture = true
  parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile, nil,
    Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
end

private def s3_piece(start : Int32, finish : Int32) : Iyi::DiagnosticLiteralWitness
  Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::StringPiece, start, finish)
end

private def s3_production(kind : Iyi::DiagnosticLiteralProduction, raw : String,
                          delimiter : String? = nil, nest : String? = nil, close : String? = nil,
                          escapes : Bool? = nil,
                          witnesses : Array(Iyi::DiagnosticLiteralWitness) = [s3_piece(0, raw.bytesize)]) : Iyi::DiagnosticLiteralProductionSegment
  Iyi::DiagnosticLiteralProductionSegment.new(kind, 0, raw.bytesize, Base64.strict_encode(raw.to_slice),
    delimiter, nest, close, escapes, witnesses)
end

private def s3_literal(input : Iyi::AcceptedCaptureInput, decoded : String, start : Int32, finish : Int32) : Iyi::DiagnosticParsedLiteral
  raw = input.input.byte_slice(start, finish - start)
  Iyi::DiagnosticParsedLiteral.new(input.input_sha256, input.input_bytesize, input.lexical_mode,
    Base64.strict_encode(decoded.to_slice), [Iyi::DiagnosticLiteralSegment.new(start, finish, Base64.strict_encode(raw.to_slice))], nil)
end

describe "S3 literal production structural model" do
  it "appends new productions without renumbering existing variants" do
    Iyi::DiagnosticLiteralProduction::PercentSymbolElement.value.should eq(3)
    Iyi::DiagnosticLiteralProduction::CharToken.value.should eq(4)
    Iyi::DiagnosticLiteralProduction::MagicFile.value.should eq(5)
    Iyi::DiagnosticLiteralProduction::MagicDir.value.should eq(6)
    Iyi::DiagnosticLiteralProduction::PercentStringElement.value.should eq(7)
    Iyi::DiagnosticLiteralProduction::Heredoc.value.should eq(8)
  end

  it "requires exactly the delimiter state and kind for each production" do
    {"STRING", "REGEX", "COMMAND"}.each { |kind| s3_production(Iyi::DiagnosticLiteralProduction::Delimiter, "xx", kind, "(", ")", true) }
    {"STRING", "REGEX", "COMMAND", "STRING_ARRAY"}.each { |kind| s3_production(Iyi::DiagnosticLiteralProduction::StringPiece, "xx", kind, "(", ")", true) }
    s3_production(Iyi::DiagnosticLiteralProduction::PercentSymbolElement, "xx", "SYMBOL_ARRAY", "(", ")", false)
    s3_production(Iyi::DiagnosticLiteralProduction::PercentStringElement, "xx", "STRING_ARRAY", "(", ")", false)
    s3_production(Iyi::DiagnosticLiteralProduction::Heredoc, "xx", "HEREDOC", "EOS", "EOS", true)
    {Iyi::DiagnosticLiteralProduction::SymbolToken, Iyi::DiagnosticLiteralProduction::CharToken,
     Iyi::DiagnosticLiteralProduction::MagicFile, Iyi::DiagnosticLiteralProduction::MagicDir}.each { |kind| s3_production(kind, "xx") }

    expect_raises(ArgumentError, "delimiter production lacks delimiter state") { s3_production(Iyi::DiagnosticLiteralProduction::PercentStringElement, "xx") }
    expect_raises(ArgumentError, "non-delimiter production has delimiter state") { s3_production(Iyi::DiagnosticLiteralProduction::CharToken, "xx", "STRING", "(", ")", true) }
    expect_raises(ArgumentError, "invalid literal delimiter production") { s3_production(Iyi::DiagnosticLiteralProduction::Delimiter, "xx", "STRING_ARRAY", "(", ")", true) }
    expect_raises(ArgumentError, "invalid literal delimiter production") { s3_production(Iyi::DiagnosticLiteralProduction::PercentStringElement, "xx", "SYMBOL_ARRAY", "(", ")", true) }
    expect_raises(ArgumentError, "invalid literal delimiter production") { s3_production(Iyi::DiagnosticLiteralProduction::Heredoc, "xx", "HEREDOC", "EOS", "OTHER", true) }
  end

  it "checks char and magic tokens as single whole-span witnesses" do
    {Iyi::DiagnosticLiteralProduction::CharToken, Iyi::DiagnosticLiteralProduction::MagicFile,
     Iyi::DiagnosticLiteralProduction::MagicDir}.each do |kind|
      input = s3_input("abc")
      literal = s3_literal(input, "x", 0, 3)
      production = s3_production(kind, "abc")
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [production], "x", input)
      bad = s3_production(kind, "abc", witnesses: [s3_piece(0, 1)])
      expect_raises(ArgumentError, "invalid symbol token witness") do
        Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [bad], "x", input)
      end
    end
  end

  it "resolves CharLiteral value at index zero and refuses a wrong field or value" do
    input = s3_input("'x'")
    literal = s3_literal(input, "x", 0, 3)
    production = s3_production(Iyi::DiagnosticLiteralProduction::CharToken, "'x'")
    char = Iyi::CharLiteral.new('x')
    Iyi::DiagnosticLiteralInputChecks.verify_owner_observation!(char, "value", 0, literal, [production], input)
    expect_raises(ArgumentError, "invalid char literal field") do
      Iyi::DiagnosticLiteralInputChecks.verify_owner_observation!(char, "name", 0, literal, [production], input)
    end
    expect_raises(ArgumentError, "literal decoded value mismatch") do
      Iyi::DiagnosticLiteralInputChecks.verify_owner_observation!(Iyi::CharLiteral.new('y'), "value", 0, literal, [production], input)
    end
  end

  it "checks a percent string element inside its enclosing production" do
    input = s3_input("%w(x)")
    literal = s3_literal(input, "x", 3, 4)
    witnesses = [Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::Opener, 0, 3),
                 s3_piece(3, 4), Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::ClosingDelimiter, 4, 5)]
    production = s3_production(Iyi::DiagnosticLiteralProduction::PercentStringElement, "%w(x)", "STRING_ARRAY", "(", ")", false, witnesses)
    Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [production], "x", input)
  end

  it "accepts REGEX and COMMAND delimiter structures in legacy mode" do
    {"REGEX", "COMMAND"}.each do |kind|
      input = s3_input("/x/")
      literal = s3_literal(input, "x", 0, 3)
      witnesses = [Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::Opener, 0, 1),
                   s3_piece(1, 2), Iyi::DiagnosticLiteralWitness.new(Iyi::DiagnosticLiteralWitnessKind::ClosingDelimiter, 2, 3)]
      production = s3_production(Iyi::DiagnosticLiteralProduction::Delimiter, "/x/", kind, "/", "/", true, witnesses)
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [production], "x", input)
    end
  end

  it "refuses heredoc evidence without independent parser replay" do
    input = s3_input("here")
    literal = s3_literal(input, "x", 0, 4)
    production = s3_production(Iyi::DiagnosticLiteralProduction::Heredoc, "here", "HEREDOC", "EOS", "EOS", true)
    expect_raises(ArgumentError, "heredoc production requires independent parser replay") do
      Iyi::DiagnosticLiteralInputChecks.verify_input_bytes!(literal, [production], "x", input)
    end
  end
end
