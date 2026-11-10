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
