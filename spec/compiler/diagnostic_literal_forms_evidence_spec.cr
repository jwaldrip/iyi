require "../support/syntax"
require "base64"

private def literal_forms_parse(source : String, capture = true, iyi = false) : Iyi::ASTNode
  parser = Iyi::Parser.new(source)
  parser.filename = "/spec/literal_forms.cr"
  parser.diagnostic_source_file = "/spec/literal_forms.cr"
  parser.iyi = iyi
  parser.diagnostic_capture = capture
  parser.parse
end

private def literal_forms_production(node : Iyi::ASTNode, field = "value", index = 0)
  node.diagnostic_literal_productions[{field, index}].first
end

describe "literal form parser evidence" do
  it "records char and magic tokens in both lexical modes without changing printed syntax" do
    [false, true].each do |iyi|
      { {"'a'", Iyi::DiagnosticLiteralProduction::CharToken},
        {"__FILE__", Iyi::DiagnosticLiteralProduction::MagicFile},
        {"__DIR__", Iyi::DiagnosticLiteralProduction::MagicDir} }.each do |source, expected|
        node = literal_forms_parse(source, iyi: iyi)
        node.to_s.should eq(literal_forms_parse(source, false, iyi).to_s)
        production = literal_forms_production(node)
        production.production.should eq(expected)
        production.witnesses.map(&.kind).should eq([Iyi::DiagnosticLiteralWitnessKind::StringPiece])
        production.witnesses.first.start_offset.should eq(0)
        production.witnesses.first.end_offset.should eq(source.bytesize)
      end
    end
  end

  it "records enclosing delimiters on regex and command bodies" do
    regex = literal_forms_parse("/abc/").as(Iyi::RegexLiteral)
    command = literal_forms_parse("`abc`").as(Iyi::Call)
    [regex.value, command.args.first].each do |body|
      production = literal_forms_production(body)
      production.production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
      production.witnesses.map(&.kind).should eq([
        Iyi::DiagnosticLiteralWitnessKind::Opener,
        Iyi::DiagnosticLiteralWitnessKind::StringPiece,
        Iyi::DiagnosticLiteralWitnessKind::ClosingDelimiter,
      ])
    end
  end

  it "records percent string elements and their implied type" do
    array = literal_forms_parse("%w(one two)").as(Iyi::ArrayLiteral)
    array.elements.each do |node|
      production = literal_forms_production(node)
      production.production.should eq(Iyi::DiagnosticLiteralProduction::PercentStringElement)
      production.witnesses.map(&.kind).should contain(Iyi::DiagnosticLiteralWitnessKind::StringPiece)
    end
    array.of.not_nil!.as(Iyi::Path).diagnostic_name_slots.should_not be_empty
  end

  it "retains evidence on scalar owners and annotation named arguments" do
    required = literal_forms_parse(%q(require "foo")).as(Iyi::Require)
    literal_forms_production(required, "string").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
    asm = literal_forms_parse(%q(asm("nop" : "=r"(x) : : "memory" : "volatile"))).as(Iyi::Asm)
    literal_forms_production(asm, "text").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
    literal_forms_production(asm.outputs.not_nil!.first, "constraint").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
    literal_forms_production(asm, "clobbers").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
    literal_forms_production(asm, "options").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
    annotation = literal_forms_parse(%q(@[Link("name": "c")])).as(Iyi::Annotation)
    literal_forms_production(annotation.named_args.not_nil!.first, "name").production.should eq(Iyi::DiagnosticLiteralProduction::Delimiter)
  end

  it "keeps heredoc indentation output and records the opener and closer" do
    source = "<<-EOS\n  value\n  EOS\n"
    node = literal_forms_parse(source).as(Iyi::StringInterpolation)
    node.to_s.should eq(literal_forms_parse(source, false).to_s)
    production = literal_forms_production(node.expressions.first)
    production.production.should eq(Iyi::DiagnosticLiteralProduction::Heredoc)
    production.witnesses.first.kind.should eq(Iyi::DiagnosticLiteralWitnessKind::Opener)
    production.witnesses.last.kind.should eq(Iyi::DiagnosticLiteralWitnessKind::ClosingDelimiter)
  end

  it "does not accept malformed quoted annotation names or unterminated literals" do
    [false, true].each do |capture|
      expect_raises(Exception) { literal_forms_parse(%q(@[Link("": 1)]), capture) }
      expect_raises(Exception) { literal_forms_parse(%q("unterminated), capture) }
    end
  end

  it "records interpolation pieces and folded percent elements" do
    node = literal_forms_parse(%q(%W(a#{x} b#{"y"}z))).as(Iyi::ArrayLiteral)
    interpolation = node.elements.first.as(Iyi::StringInterpolation)
    literal_forms_production(interpolation.expressions.first).production.should eq(Iyi::DiagnosticLiteralProduction::StringPiece)
    folded = node.elements.last.as(Iyi::StringLiteral)
    Base64.decode(folded.diagnostic_literal_names[{"value", 0}].decoded_base64).should eq("byz".to_slice)
    literal_forms_production(folded).production.should eq(Iyi::DiagnosticLiteralProduction::PercentStringElement)
  end

  it "leaves literal syntax and heredoc indentation errors unchanged with capture enabled" do
    sources = [%q("plain"), %q(%q(a\)b)), %q(%Q(x)), %q(%[x]), %q(:name),
               %q(:"quoted name"), %q("a#{"b"}"), %q(%w(a b)), %q(%i(a b)),
               %q(/a\/b/i), %q(`a#{x}`), "<<-'EOS'\n  text\n  EOS\n"]
    [false, true].each do |iyi|
      sources.each do |source|
        literal_forms_parse(source, true, iyi).to_s.should eq(literal_forms_parse(source, false, iyi).to_s)
      end
    end
    source = "<<-EOS\nx\n  EOS\n"
    [false, true].each do |capture|
      expect_raises(Exception, /heredoc line must have an indent/) { literal_forms_parse(source, capture) }
    end
  end

  it "preserves distinct adjacent string segment spans" do
    source = "\"a\" \\\n \"b\""
    node = literal_forms_parse(source).as(Iyi::StringLiteral)
    segments = node.diagnostic_literal_productions[{"value", 0}]
    segments.size.should eq(2)
    segments.last.witnesses.first.kind.should eq(Iyi::DiagnosticLiteralWitnessKind::Continuation)
    Base64.decode(node.diagnostic_literal_names[{"value", 0}].decoded_base64).should eq("ab".to_slice)
  end

  it "refuses invalid quoted-name derivations" do
    expect_raises(ArgumentError, "invalid quoted name") do
      Iyi::DiagnosticOrigin::DerivedName.quoted_name("named_entry", "a" * 64, 5, "Crystal", 0, 5, "a b")
    end
    expect_raises(ArgumentError, "invalid quoted name") do
      Iyi::DiagnosticOrigin::DerivedName.quoted_name("wrong_context", "a" * 64, 5, "Crystal", 0, 5, "abc")
    end
  end
  it "associates asm and operand boundaries with replayed owners" do
    source = %q(asm("nop" : "=r"(x) : : "memory" : "volatile"))
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/literal_forms.cr"
    parser.enable_diagnostic_observations
    node = parser.parse.as(Iyi::Asm)
    observations = parser.diagnostic_scalar_grammar_observations
    journal = parser.diagnostic_lexical_observations
    asm = observations.find { |item| item.owner.same?(node) }.not_nil!
    operand = observations.find { |item| item.owner.same?(node.outputs.not_nil!.first) }.not_nil!
    journal[asm.first.ordinal].token_text.should eq("asm")
    journal[asm.open.not_nil!.ordinal].token_text.should eq("(")
    journal[asm.close.ordinal].token_text.should eq(")")
    journal[operand.first.ordinal].token_text.should eq("\"")
    journal[operand.open.not_nil!.ordinal].token_text.should eq("(")
    journal[operand.close.ordinal].token_text.should eq(")")
    operand.expression.should be(node.outputs.not_nil!.first.exp)
    journal[operand.expression_first.not_nil!.ordinal].token_text.should eq("x")
  end

  it "associates folded interpolation with the original expression" do
    source = %q(require "x#{"y"}")
    parser = Iyi::Parser.new(source)
    parser.filename = "/spec/literal_forms.cr"
    parser.enable_diagnostic_observations
    parser.parse
    fold = parser.diagnostic_folded_string_observations.first
    journal = parser.diagnostic_lexical_observations
    journal[fold.open.ordinal].token_text.should eq(%q(#{))
    journal[fold.close.ordinal].token_text.should eq("}")
    fold.expression.value.should eq("y")
  end
  it "distinguishes neighboring asm owners and their journal ordinals" do
    parser = Iyi::Parser.new(%q(asm("nop"); asm("nop")))
    parser.filename = "/spec/literal_forms.cr"
    parser.enable_diagnostic_observations
    nodes = parser.parse.as(Iyi::Expressions).expressions
    observations = parser.diagnostic_scalar_grammar_observations.select { |item| item.kind.asm? }
    observations.size.should eq(2)
    observations[0].owner.should be(nodes[0])
    observations[1].owner.should be(nodes[1])
    observations[0].first.ordinal.should be < observations[1].first.ordinal
  end

  it "associates a nested asm with its containing operand expression" do
    parser = Iyi::Parser.new(%q(asm("outer" : "=r"(asm("inner")))))
    parser.filename = "/spec/literal_forms.cr"
    parser.enable_diagnostic_observations
    outer = parser.parse.as(Iyi::Asm)
    operand = outer.outputs.not_nil!.first
    observations = parser.diagnostic_scalar_grammar_observations
    inner = operand.exp.as(Iyi::Asm)
    operand_observation = observations.find { |item| item.owner.same?(operand) }.not_nil!
    inner_observation = observations.find { |item| item.owner.same?(inner) }.not_nil!
    operand_observation.expression.should be(inner)
    inner_observation.first.ordinal.should be >= operand_observation.expression_first.not_nil!.ordinal
  end
end
