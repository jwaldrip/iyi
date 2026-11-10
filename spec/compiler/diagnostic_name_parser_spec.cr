require "../support/syntax"

describe "rendered macro observation" do
  it "observes real macro-state tokens and preserves output in both modes" do
    source = "\uFEFFmacro sample\n  {% if true %}\n    {{ value }}\n  {% end %}\nend\n"
    ["Crystal", "Iyi"].each do |mode|
      node, tokens = Iyi::Parser.observe_rendered_macro(source, mode)
      tokens.count { |token| token.token_kind == "MACRO_CONTROL_START" }.should eq(2)
      tokens.count { |token| token.token_kind == "MACRO_EXPRESSION_START" }.should eq(1)
      tokens.each do |token|
        token.input_start.should be >= 3
        token.token_text.should eq(source.byte_slice(token.input_start, token.input_end - token.input_start))
        token.lexical_mode.should eq(mode)
      end
      ordinary = Iyi::Parser.new(source)
      ordinary.iyi = mode == "Iyi"
      node.to_s.should eq(ordinary.parse.to_s)
    end
  end

  it "rolls back observations from a failed lookahead" do
    parser = Iyi::Parser.new("alpha beta")
    parser.enable_diagnostic_observations
    parser.next_token
    before = parser.diagnostic_lexical_observations
    parser.peek_ahead { parser.next_token_skip_space }
    parser.diagnostic_lexical_observations.should eq(before)
    parser.next_token_skip_space
    parser.diagnostic_lexical_observations.size.should be > before.size
  end

  it "rejects invalid modes and more than one top-level expression" do
    expect_raises(ArgumentError) { Iyi::Parser.observe_rendered_macro("macro sample\nend", "unknown") }
    expect_raises(ArgumentError) { Iyi::Parser.observe_rendered_macro("macro sample\nend\nother", "Crystal") }
  end
end

describe "parameter name provenance" do
  it "distinguishes written external names from implicit and lowered defaults" do
    {
      {"def f(arg); end", false},
      {"def f(external internal); end", true},
      { %q(def f("external" internal); end), true},
      {"def f(@select); end", false},
      {"def f(external @select); end", true},
    }.each do |source, explicit|
      parser = Iyi::Parser.new(source)
      parser.filename = "/spec/parameter.cr"
      parser.diagnostic_source_file = "/spec/parameter.cr"
      parser.diagnostic_capture = true
      arg = parser.parse.as(Iyi::Def).args.first
      arg.diagnostic_external_explicit.should eq(explicit)
    end
  end
end

# A fresh replay parser over one declaration, with the journal and capture the binder reads from.
def bare_splat_spec_parser(source : String, iyi : Bool = false) : Iyi::Parser
  parser = Iyi::Parser.new(source)
  parser.iyi = iyi
  parser.filename = "/spec/bare_splat.cr"
  parser.diagnostic_source_file = "/spec/bare_splat.cr"
  parser.enable_diagnostic_observations
  parser.diagnostic_capture = true
  parser
end

describe "bare splat parameter observation" do
  it "observes the declaration keyword, star, and comma of a bare splat in both modes" do
    ["def f(*, y); end", "macro f(*, y); end"].each do |source|
      [false, true].each do |iyi|
        parser = bare_splat_spec_parser(source, iyi)
        node = parser.parse
        observations = parser.diagnostic_bare_splat_observations
        observations.size.should eq(1)
        observation = observations.first
        observation.owner.same?(node).should eq(true)
        observation.index.should eq(0)
        observation.argument.name.should eq("")
        journal = parser.diagnostic_lexical_observations
        journal[observation.keyword.ordinal].token_text.should eq(source.split(' ').first)
        journal[observation.star.ordinal].token_text.should eq("*")
        journal[observation.comma.ordinal].token_text.should eq(",")
        primary = Iyi::DiagnosticNameSlot.new(Iyi::DiagnosticNameSlotKind::Primary)
        value = observation.argument.diagnostic_name_slots[primary].first.as(Iyi::DiagnosticNameValue::Derived)
        expected = source.starts_with?("macro") ? Iyi::DiagnosticStructuralProduction::MacroBareSplatParameter : Iyi::DiagnosticStructuralProduction::BareSplatParameter
        value.origin.structural_production.should eq(expected)
        value.rendered_text.should eq("")
      end
    end
  end

  it "records nothing for an ordinary parse, a named splat, or a rolled-back lookahead" do
    ordinary = Iyi::Parser.new("def f(*, y); end")
    ordinary.parse
    ordinary.diagnostic_bare_splat_observations.should eq([] of Iyi::DiagnosticBareSplatObservation)

    named = bare_splat_spec_parser("def f(*xs, y); end")
    named.parse
    named.diagnostic_bare_splat_observations.should eq([] of Iyi::DiagnosticBareSplatObservation)

    rolled = bare_splat_spec_parser("def f(*, y); end")
    rolled.lookahead { rolled.parse; nil }
    rolled.diagnostic_bare_splat_observations.should eq([] of Iyi::DiagnosticBareSplatObservation)
  end
end
