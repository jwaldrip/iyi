require "../support/syntax"
require "base64"

private def parse_literal_capture(source : String) : Iyi::ASTNode
  parser = Iyi::Parser.new(source)
  parser.filename = "/spec/literal_capture.cr"
  parser.diagnostic_source_file = "/spec/literal_capture.cr"
  parser.diagnostic_capture = true
  parser.parse
end

private def assert_literal_capture(node : Iyi::ASTNode, field : String, index : Int32,
                                   source : String, raw : String, decoded : Bytes) : Nil
  literal = node.diagnostic_literal_names[{field, index}]
  literal.input_sha256.should eq(::Crystal::Digest::SHA256.hexdigest(source))
  literal.input_bytesize.should eq(source.bytesize)
  literal.lexical_mode.should eq("Crystal")
  Base64.decode(literal.decoded_base64).should eq(decoded)
  literal.segments.size.should eq(1)
  segment = literal.segments.first
  source.byte_slice(segment.start_offset, segment.end_offset - segment.start_offset).should eq(raw)
  Base64.decode(segment.raw_base64).should eq(raw.to_slice)
  production = node.diagnostic_literal_productions[{field, index}].first
  production.start_offset.should eq(segment.start_offset)
  production.end_offset.should eq(segment.end_offset)
  production.raw_base64.should eq(segment.raw_base64)
  production.witnesses.should_not be_empty
end

describe "parsed literal name evidence" do
  it "retains the actual pre-parse input and refuses a consumed parser" do
    source = "\uFEFF" + %q(f("key": 1))
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/literal_capture.cr"
    parser.diagnostic_source_file = "/spec/literal_capture.cr"
    parser.diagnostic_capture = true
    input = parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
      nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    input.input.should eq(source)
    input.input_sha256.should eq(::Crystal::Digest::SHA256.hexdigest(source))
    parser.parse
    expect_raises(ArgumentError) do
      parser.diagnostic_capture_input(Iyi::DiagnosticCaptureInputKind::SourceFile,
        nil, Iyi::DiagnosticCaptureParseEntry::Parse, Iyi::Parser::ParseMode::Normal)
    end
  end

  it "keeps distinct first and later named tuple keys and clone evidence" do
    source = %q({"first": 1, "second": 2})
    tuple = parse_literal_capture(source).as(Iyi::NamedTupleLiteral)
    assert_literal_capture(tuple, "entries.key", 0, source, %q("first"), "first".to_slice)
    assert_literal_capture(tuple, "entries.key", 1, source, %q("second"), "second".to_slice)
    copy = tuple.clone
    tuple.diagnostic_literal_names.clear
    assert_literal_capture(copy, "entries.key", 1, source, %q("second"), "second".to_slice)
  end

  it "records first and later call keys and arbitrary decoded bytes" do
    source = %q(f("first": 1, "\xFF": 2))
    args = parse_literal_capture(source).as(Iyi::Call).named_args.not_nil!
    assert_literal_capture(args[0], "name", 0, source, %q("first"), "first".to_slice)
    assert_literal_capture(args[1], "name", 0, source, %q("\xFF"), Bytes[255])
  end

  it "records quoted generic type names" do
    source = %q(def f(x : Foo("key": T)); end)
    generic = parse_literal_capture(source).as(Iyi::Def).args.first.restriction.as(Iyi::Generic)
    arg = generic.named_args.not_nil!.first
    assert_literal_capture(arg, "name", 0, source, %q("key"), "key".to_slice)
  end

  it "records an explicit external parameter separately from its internal name" do
    source = %q(def f("external" local); end)
    arg = parse_literal_capture(source).as(Iyi::Def).args.first
    assert_literal_capture(arg, "external_name", 0, source, %q("external"), "external".to_slice)
    arg.name.should eq("local")
  end

  it "records a foreign symbol alias and a quoted symbol literal" do
    source = %q(lib Lib; fun local = "foreign name"; end)
    fun = parse_literal_capture(source).as(Iyi::LibDef).body.as(Iyi::FunDef)
    assert_literal_capture(fun, "real_name", 0, source, %q("foreign name"), "foreign name".to_slice)
    symbol_source = %q(:"a b")
    symbol = parse_literal_capture(symbol_source).as(Iyi::SymbolLiteral)
    assert_literal_capture(symbol, "value", 0, symbol_source, symbol_source, "a b".to_slice)
  end

  it "records interpolation witnesses even when the parser folds a constant literal" do
    source = %q(f("a#{"b"}": 1))
    argument = parse_literal_capture(source).as(Iyi::Call).named_args.not_nil!.first
    literal = argument.diagnostic_literal_names[{"name", 0}]
    Base64.decode(literal.decoded_base64).should eq("ab".to_slice)
    witnesses = argument.diagnostic_literal_productions[{"name", 0}].first.witnesses
    witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::InterpolationStart)
    witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::InterpolationEnd)
    witnesses.each do |witness|
      witness.start_offset.should be < witness.end_offset
      witness.end_offset.should be <= source.bytesize
    end
  end

  it "records the enclosing percent-symbol delimiters and each element" do
    source = "%i(first second)"
    symbols = parse_literal_capture(source).as(Iyi::ArrayLiteral).elements
    symbols.size.should eq(2)
    symbols.each_with_index do |node, index|
      literal = node.diagnostic_literal_names[{"value", 0}]
      Base64.decode(literal.decoded_base64).should eq((index == 0 ? "first" : "second").to_slice)
      production = node.diagnostic_literal_productions[{"value", 0}].first
      production.production.should eq(Iyi::DiagnosticLiteralProduction::PercentSymbolElement)
      Base64.decode(production.raw_base64).should eq(source.to_slice)
      production.witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::Opener)
      production.witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::StringPiece)
      production.witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::ClosingDelimiter)
    end
  end
end
