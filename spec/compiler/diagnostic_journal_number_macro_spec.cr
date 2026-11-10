require "../support/syntax"
require "base64"

# Numeric and macro-literal journal records: the value and kind the lexer itself set.
private def numeric_journal(source : String, iyi : Bool = false) : Array(Iyi::DiagnosticRenderedToken)
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations
  loop { break if lexer.next_token.type.eof? }
  lexer.diagnostic_lexical_observations.reject { |observation| observation.token_kind == "EOF" }
end

# Macro text through `next_macro_token`, the way the parser drives it, until the macro ends.
private def numeric_macro_journal(source : String, iyi : Bool = false) : Array(Iyi::DiagnosticRenderedToken)
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations
  state = Iyi::Token::MacroState.default
  loop do
    token = lexer.next_macro_token(state, false)
    break if token.type.macro_end? || token.type.eof?
    state = token.macro_state
  end
  lexer.diagnostic_lexical_observations.reject { |observation| observation.token_kind == "EOF" }
end

private def numeric_decoded(observation : Iyi::DiagnosticRenderedToken) : String
  String.new(Base64.decode(observation.value_base64.not_nil!))
end

# Each token as the parser reads it. Journal on and off must agree.
private def numeric_stream(source : String, iyi : Bool, journal : Bool) : Array({String, String, Int32, Int32, Int32, String})
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations if journal
  stream = [] of {String, String, Int32, Int32, Int32, String}
  loop do
    token = lexer.next_token
    stream << {token.type.to_s, token.value.inspect, token.input_offset, token.input_end,
               token.line_number, token.number_kind.to_s}
    break if token.type.eof?
  end
  stream
end

private def numeric_macro_stream(source : String, iyi : Bool, journal : Bool) : Array({String, String, Int32, Int32})
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations if journal
  stream = [] of {String, String, Int32, Int32}
  state = Iyi::Token::MacroState.default
  loop do
    token = lexer.next_macro_token(state, false)
    stream << {token.type.to_s, token.value.inspect, token.input_offset, token.input_end}
    break if token.type.macro_end? || token.type.eof?
    state = token.macro_state
  end
  stream
end

# The message a lex raises, or "no error", with the journal on or off.
private def numeric_scan_outcome(source : String, iyi : Bool, journal : Bool) : String
  lexer = Iyi::Lexer.new(source)
  lexer.iyi = iyi
  lexer.enable_diagnostic_observations if journal
  loop { break if lexer.next_token.type.eof? }
  "no error"
rescue ex : Exception
  "#{ex.class}: #{ex.message}"
end

# The §4 J acceptance table: source, the value the journal must carry, and the kind.
NUMERIC_JOURNAL_CASES = [
  {"-1", "-1", "i32"},
  {"+1", "+1", "i32"},
  {"1_000", "1000", "i32"},
  {"0x7fffffffffffffff", "9223372036854775807", "i64"},
  {"0xffffffffffffffffffffffffffffffffu128", "340282366920938463463374607431768211455", "u128"},
  {"-0x80_i8", "-128", "i8"},
  {"1.5E-3_f32", "1.5E-3", "f32"},
  {"1e400", "1e400", "f64"},
  {"9223372036854775808", "9223372036854775808", "u64"},
]

describe "Iyi::Lexer numeric and macro journal" do
  [{"Crystal", false}, {"Iyi", true}].each do |mode, iyi|
    describe "in #{mode} mode" do
      it "records the value and kind of each NUMBER, matching the lexer's own token" do
        NUMERIC_JOURNAL_CASES.each do |source, value, kind|
          lexer = Iyi::Lexer.new(source)
          lexer.iyi = iyi
          token = lexer.next_token
          token.type.number?.should be_true
          token.value.to_s.should eq value
          token.number_kind.to_s.should eq kind

          observation = numeric_journal(source, iyi).find! { |entry| entry.token_kind == "NUMBER" }
          observation.lexical_mode.should eq mode
          observation.number_kind.should eq kind
          numeric_decoded(observation).should eq value
          observation.token_text.should eq source
        end
      end

      it "records __LINE__ with the line it is on, and no kind" do
        observations = numeric_journal("\n\n__LINE__", iyi)
        observations.map(&.token_kind).should eq ["NEWLINE", "NEWLINE", "__LINE__"]
        line = observations[2]
        line.token_text.should eq "__LINE__"
        line.line.should eq 3
        line.number_kind.should be_nil
        numeric_decoded(line).should eq "3"
      end

      it "records MACRO_LITERAL with the value the lexer set" do
        observations = numeric_macro_journal("hello world", iyi)
        observations.map(&.token_kind).should eq ["MACRO_LITERAL"]
        observations[0].token_text.should eq "hello world"
        observations[0].number_kind.should be_nil
        numeric_decoded(observations[0]).should eq "hello world"
      end

      it "records an escaped brace as its raw text with the unescaped value" do
        observations = numeric_macro_journal("\\{{x}}", iyi)
        first = observations[0]
        first.token_kind.should eq "MACRO_LITERAL"
        first.token_text.should eq "\\{"
        numeric_decoded(first).should eq "{"
      end

      it "leaves a failed lookahead over a NUMBER with the journal size it had" do
        lexer = Iyi::Lexer.new("123 x")
        lexer.iyi = iyi
        lexer.enable_diagnostic_observations
        before = lexer.diagnostic_lexical_observations.size
        lexer.lookahead { lexer.next_token; false }.should be_false
        lexer.diagnostic_lexical_observations.size.should eq before

        lexer.next_token.number_kind.should eq Iyi::NumberKind::I32
        observation = lexer.diagnostic_lexical_observations.find! { |entry| entry.token_kind == "NUMBER" }
        numeric_decoded(observation).should eq "123"
      end

      it "raises the same error with the journal on and off when a literal does not fit its kind" do
        on = numeric_scan_outcome("128_i8", iyi, true)
        off = numeric_scan_outcome("128_i8", iyi, false)
        on.should eq off
        on.should_not eq "no error"
      end

      it "returns the same token stream with the journal on and off" do
        [
          "-1 +1 1_000 0x7fffffffffffffff",
          "0xffffffffffffffffffffffffffffffffu128 -0x80_i8 1.5E-3_f32 1e400",
          "9223372036854775808",
          "\n\n__LINE__ __LINE__",
        ].each do |source|
          numeric_stream(source, iyi, false).should eq numeric_stream(source, iyi, true)
        end
        ["hello world", "\\{{x}}", "a \\% b"].each do |source|
          numeric_macro_stream(source, iyi, false).should eq numeric_macro_stream(source, iyi, true)
        end
      end

      it "accepts a NUMBER value longer than its raw text, up to the decimal bound" do
        observation = Iyi::DiagnosticRenderedToken.new(0, 18, "NUMBER", "0x7fffffffffffffff", mode,
          Base64.strict_encode("9223372036854775807".to_slice), nil, false, false, nil, number_kind: "i64")
        observation.number_kind.should eq "i64"
        Base64.decode(observation.value_base64.not_nil!).should eq "9223372036854775807".to_slice
      end

      it "refuses a number kind on a non-number token" do
        expect_raises(ArgumentError, "number kind on a non-number token") do
          Iyi::DiagnosticRenderedToken.new(0, 1, "IDENT", "a", mode, nil, nil, false, false, nil, number_kind: "i32")
        end
      end

      it "refuses an unknown number kind" do
        expect_raises(ArgumentError, "invalid number kind") do
          Iyi::DiagnosticRenderedToken.new(0, 1, "NUMBER", "1", mode, Base64.strict_encode("1".to_slice),
            nil, false, false, nil, number_kind: "i33")
        end
      end

      it "refuses a NUMBER whose value and kind differ in presence" do
        expect_raises(ArgumentError, "number value and kind differ in presence") do
          Iyi::DiagnosticRenderedToken.new(0, 1, "NUMBER", "1", mode, nil, nil, false, false, nil, number_kind: "i32")
        end
        expect_raises(ArgumentError, "number value and kind differ in presence") do
          Iyi::DiagnosticRenderedToken.new(0, 1, "NUMBER", "1", mode, Base64.strict_encode("1".to_slice))
        end
      end

      it "refuses a __LINE__ value longer than a line number can be" do
        expect_raises(ArgumentError, "rendered value exceeds token bound") do
          Iyi::DiagnosticRenderedToken.new(0, 8, "__LINE__", "__LINE__", mode,
            Base64.strict_encode("1234567890123".to_slice))
        end
      end
    end
  end
end
